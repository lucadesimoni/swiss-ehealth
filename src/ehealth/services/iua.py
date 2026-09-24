# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""IUA: access tokens for the national FHIR interfaces (CH EPR FHIR v5.0.0).

The guide requires every MHD, PIXm/PDQm and CH:ATC request to carry an IUA
access token (ITI-72). This module is both ends of that:

**Authorization Server** (ITI-71, ITI-103). Registered portals, primary
systems and archive systems obtain signed JWT access tokens:

* ``client_credentials`` — the *Technical User* option. An archive system
  writes on behalf of the healthcare professional registered for it at
  onboarding (``principal_id`` must be that GLN); scope
  ``purpose_of_use=…|AUTO subject_role=…|TCU``.
* ``authorization_code`` with PKCE — the *Workflow Initiator* option. The
  user is identified either by this system's own login session (the user
  signed in here, with SwissID/HIN/AGOV and a second factor) or by the ID
  token the portal presents as ``client_assertion``.
* ``urn:ietf:params:oauth:grant-type:jwt-bearer`` — the same, without the
  redirect: the portal presents the ID token as ``assertion``.

Without ``person_id`` the token is a **Basic Access Token** (PIXm/PDQm).
With it, an **Extended Access Token** for that patient's record (MHD, ATC),
carrying ``subject_role``, ``purpose_of_use`` and ``person_id``.

Every token request must be signed by the client (RFC 9421, see
:mod:`ehealth.security.httpsig`). Tokens are JWS, never JWE, and never
HMAC-signed: RS256 by default, which every IUA resource server must accept.

**Resource Server** (ITI-72). A token is verified — signature, issuer,
audience, lifetime, registry — and then **authorised against the record as it
is now**: the patient's consent is evaluated again on every request, a
professional's role and licence must still be live, and the EPR-SPID in the
token must name the record the request touches. A token is a statement of
who is asking and why; it is never on its own the permission.

What is not implemented, and refused rather than half-supported: the
Assistant (ASS) and Representative (REP) roles, SMART on FHIR ``launch``,
SAML assertions, tokens from other communities' authorization servers, and
Token Introspection (which the guide forbids anyway).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, NoReturn
from urllib.parse import unquote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.config import IuaClientSettings, Settings
from ehealth.db import utcnow
from ehealth.domain.uid import new_uid
from ehealth.models.audit import AuditAction, AuditOutcome
from ehealth.models.auth import AccountStatus, IdentityAccount
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.clinical import Dossier, DossierStatus
from ehealth.models.core import Person, PersonRoleKind, PersonStatus
from ehealth.models.governance import IssuedToken
from ehealth.security.crypto import (
    CryptoError,
    KeyPurpose,
    KeyRing,
    b64u,
    b64u_decode,
    constant_time_equals,
    sha256,
)
from ehealth.security.httpsig import SignatureError, load_public_key, verify_request
from ehealth.security.oidc import OidcError, _verify_jws, public_jwk
from ehealth.security.tokens import Scope
from ehealth.services.access import (
    ConsentService,
    evaluate_policy,
)
from ehealth.services.audit import ActorContext, AuditLedger, commit_security_event
from ehealth.services.patient_directory import EPR_SPID_OID

# -- vocabulary -------------------------------------------------------------

PURPOSE_OF_USE_SYSTEM = "urn:oid:2.16.756.5.30.1.127.3.10.5"
ROLE_SYSTEM = "urn:oid:2.16.756.5.30.1.127.3.10.6"
#: The client-credentials table of the guide names this OID for the role
#: code system while every example uses ``…10.6``. Both are accepted in a
#: request; tokens always carry ``…10.6``.
ROLE_SYSTEM_ALTERNATIVE = "urn:oid:2.16.756.5.30.1.127.3.10.1.1.3"

GRANT_AUTHORIZATION_CODE = "authorization_code"
GRANT_CLIENT_CREDENTIALS = "client_credentials"
GRANT_JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105
JWT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

QUALIFIER_EPR_SPID = "urn:e-health-suisse:2015:epr-spid"
QUALIFIER_GLN = "urn:gs1:gln"

#: JOSE ``typ`` of IUA access tokens (RFC 9068). Distinguishes them from this
#: system's own session and capability tokens, whose ``typ`` is ``CAP``.
ACCESS_TOKEN_TYP = "at+jwt"  # noqa: S105

KIND_BASIC = "iua-basic"
KIND_EXTENDED = "iua-extended"
KIND_CODE = "iua-code"

ACCEPTED_ALGORITHMS = frozenset({"RS256", "ES256"})


class Role(StrEnum):
    PATIENT = "PAT"
    HEALTHCARE_PROFESSIONAL = "HCP"
    ASSISTANT = "ASS"
    REPRESENTATIVE = "REP"
    TECHNICAL_USER = "TCU"


class PurposeOfUse(StrEnum):
    NORMAL = "NORM"
    EMERGENCY = "EMER"
    AUTOMATIC = "AUTO"


#: What each role may do with an extended token, whatever else it asks for.
ROLE_SCOPES: dict[Role, frozenset[Scope]] = {
    Role.PATIENT: frozenset(
        {Scope.DOCUMENT_READ, Scope.DOCUMENT_WRITE, Scope.AUDIT_READ}
    ),
    Role.HEALTHCARE_PROFESSIONAL: frozenset(
        {Scope.DOCUMENT_READ, Scope.DOCUMENT_WRITE}
    ),
    # An archive system writes; it never reads a record (guide use case
    # "Writing documents from clinical archives").
    Role.TECHNICAL_USER: frozenset({Scope.DOCUMENT_WRITE}),
}

#: A basic token only reaches the patient-identity interfaces.
BASIC_SCOPES = frozenset({Scope.PERSON_READ})

_PURPOSES: dict[tuple[Role, PurposeOfUse], Purpose] = {
    (Role.PATIENT, PurposeOfUse.NORMAL): Purpose.PATIENT_ACCESS,
    (Role.HEALTHCARE_PROFESSIONAL, PurposeOfUse.NORMAL): Purpose.TREATMENT,
    (Role.HEALTHCARE_PROFESSIONAL, PurposeOfUse.EMERGENCY): Purpose.EMERGENCY,
    (Role.TECHNICAL_USER, PurposeOfUse.AUTOMATIC): Purpose.TREATMENT,
}


class IuaError(Exception):
    """A refused IUA request.

    ``error`` is the OAuth error code returned to the client; ``reason`` is
    the real cause, which goes to the audit trail and never to the caller.
    """

    def __init__(self, status: int, error: str, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.error = error
        self.reason = reason


def _refuse(reason: str, error: str = "invalid_grant") -> NoReturn:
    # The guide: a failed check at the authorization server is a 401.
    raise IuaError(401, error, reason)


def _malformed(reason: str) -> NoReturn:
    raise IuaError(400, "invalid_request", reason)


# -- parsing ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RequestedScope:
    role: Role | None
    purpose: PurposeOfUse | None
    other: tuple[str, ...]
    launch: bool

    @property
    def text(self) -> str:
        parts = list(self.other)
        if self.purpose:
            parts.append(f"purpose_of_use={PURPOSE_OF_USE_SYSTEM}|{self.purpose}")
        if self.role:
            parts.append(f"subject_role={ROLE_SYSTEM}|{self.role}")
        return " ".join(parts)


def parse_scope(scope: str) -> RequestedScope:
    role = purpose = None
    other: list[str] = []
    launch = False
    for item in (scope or "").split():
        name, eq, value = item.partition("=")
        if not eq:
            if name == "launch" or name.startswith("launch/"):
                launch = True
            other.append(name)
            continue
        system, bar, code = unquote(value).rpartition("|")
        if not bar:
            _malformed(f"scope {name} is not in token format")
        if name == "purpose_of_use":
            if system != PURPOSE_OF_USE_SYSTEM:
                _malformed("purpose_of_use uses an unknown code system")
            try:
                purpose = PurposeOfUse(code)
            except ValueError:
                _malformed(f"unknown purpose_of_use {code!r}")
        elif name == "subject_role":
            if system not in (ROLE_SYSTEM, ROLE_SYSTEM_ALTERNATIVE):
                _malformed("subject_role uses an unknown code system")
            try:
                role = Role(code)
            except ValueError:
                _malformed(f"unknown subject_role {code!r}")
        else:
            other.append(item)
    return RequestedScope(role, purpose, tuple(other), launch)


def parse_person_id(value: str) -> str:
    """The EPR-SPID from a CX value ``761337…^^^&2.16.756.5.30.1.127.3.10.3&ISO``.

    Only the EPR-SPID domain is accepted: the guide defines ``person_id`` as
    the EPR-SPID, and a local or AHV number here would sidestep the check that
    ties the token to one national record.
    """
    identifier, sep, authority = unquote(value).partition("^^^")
    parts = authority.split("&")
    if (
        not sep
        or not identifier.isdigit()
        or len(parts) != 3
        or parts[1] != EPR_SPID_OID
        or parts[2] != "ISO"
    ):
        _malformed("person_id must be an EPR-SPID in CX format")
    return identifier


def format_person_id(spid: str) -> str:
    return f"{spid}^^^&{EPR_SPID_OID}&ISO"


# -- the signing key ------------------------------------------------------------


class IuaSigningKey:
    """The authorization server's JWS key: RSA (RS256) or EC P-256 (ES256)."""

    def __init__(self, pem: str, key_id: str) -> None:
        if pem:
            key = serialization.load_pem_private_key(pem.encode("ascii"), None)
        else:
            # Development only: Settings refuses production without a key.
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if isinstance(key, rsa.RSAPrivateKey):
            if key.key_size < 2048:
                raise ValueError("the IUA signing key must be at least 2048 bits")
            self.algorithm = "RS256"
        elif isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(
            key.curve, ec.SECP256R1
        ):
            self.algorithm = "ES256"
        else:
            raise ValueError("the IUA signing key must be RSA or EC P-256")
        self._key = key
        self.key_id = key_id
        self._public_jwk = public_jwk(key.public_key(), key_id)
        self._public = key.public_key()

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self._public_jwk]}

    def sign(self, claims: dict[str, Any]) -> str:
        header = {"alg": self.algorithm, "typ": ACCESS_TOKEN_TYP, "kid": self.key_id}
        head = b64u(json.dumps(header, separators=(",", ":")).encode())
        body = b64u(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{head}.{body}".encode("ascii")
        if self.algorithm == "RS256":
            signature = self._key.sign(
                signing_input, padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            r, s = decode_dss_signature(
                self._key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            )
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{head}.{body}.{b64u(signature)}"

    def verify(self, token: str) -> dict[str, Any]:
        """Signature and header only. Claims are checked by the caller."""
        if len(token) > 16_384:
            _refuse("token is implausibly large", "invalid_token")
        parts = token.split(".")
        if len(parts) != 3:
            _refuse("token is not a compact JWS", "invalid_token")
        head, body, signature = parts
        try:
            header = json.loads(b64u_decode(head))
            claims = json.loads(b64u_decode(body))
            raw_signature = b64u_decode(signature)
        except (CryptoError, ValueError):
            _refuse("token is malformed", "invalid_token")
        if not isinstance(header, dict) or not isinstance(claims, dict):
            _refuse("token segments must be JSON objects", "invalid_token")
        algorithm = header.get("alg")
        # The algorithm is the key's, not the token's: "none", HMAC and a
        # swap between RSA and EC are all refused here.
        if algorithm not in ACCEPTED_ALGORITHMS or algorithm != self.algorithm:
            _refuse(f"unacceptable algorithm {algorithm!r}", "invalid_token")
        if header.get("typ") != ACCESS_TOKEN_TYP:
            _refuse("not an IUA access token", "invalid_token")
        if header.get("kid") != self.key_id:
            _refuse("unknown key id", "invalid_token")
        if "crit" in header:
            _refuse("critical header extensions are not supported", "invalid_token")
        if not _verify_jws(
            self._public, algorithm, f"{head}.{body}".encode("ascii"), raw_signature
        ):
            _refuse("signature does not verify", "invalid_token")
        return claims


def looks_like_iua_token(token: str) -> bool:
    """True when the bearer token's JOSE header says it is an IUA token.

    Only a routing decision: which verifier to hand the token to. The
    verifier then checks everything, including the header again.
    """
    head = token.split(".", 1)[0]
    try:
        header = json.loads(b64u_decode(head))
    except (CryptoError, ValueError):
        return False
    return isinstance(header, dict) and header.get("typ") == ACCESS_TOKEN_TYP


# -- what a verified request is -------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenRequest:
    """A token endpoint request as it arrived, for signature checking."""

    method: str
    target_uri: str
    #: Lower-case header names.
    headers: dict[str, str]
    body: bytes
    form: dict[str, str]


@dataclass(frozen=True, slots=True)
class _Subject:
    """Who a token will be issued for, after every check has passed."""

    person: Person
    role: Role
    purpose: PurposeOfUse | None
    spid: str | None
    scope: RequestedScope
    gln: str | None = None
    #: Technical User: the professional's name as the client gave it.
    principal_name: str | None = None
    #: The authorisation code this token is redeemed from, if any.
    code_jti: str | None = None
    via: str = ""


@dataclass(frozen=True, slots=True)
class IuaAccess:
    """A request authorised by an IUA token, at the moment of the request.

    Carries the same three things the dossier services read from a
    capability — ``dossier_uid``, ``max_level`` and ``actor`` — so a document
    read through MHD is filtered exactly like one read through the native
    API.
    """

    jti: str
    subject_uid: str
    role: Role
    purpose: Purpose | None
    dossier_uid: str | None
    patient_uid: str | None
    max_level: Confidentiality
    scopes: frozenset[Scope]
    actor: ActorContext
    extended: bool = field(default=False)

    def has_scope(self, scope: Scope) -> bool:
        return scope in self.scopes


# -- the service ----------------------------------------------------------------


class IuaService:
    """Authorization Server and Resource Server in one place, because both
    have to agree on every claim, and a disagreement between two copies of
    that knowledge would be a vulnerability."""

    def __init__(
        self,
        settings: Settings,
        keyring: KeyRing,
        signing_key: IuaSigningKey,
        *,
        persons,
        consents: ConsentService,
        ledger: AuditLedger,
        identity_verifiers: dict[str, Any] | None = None,
        assurance_policies: dict[str, Any] | None = None,
    ) -> None:
        self._keyring = keyring
        self._key = signing_key
        self._persons = persons
        self._consents = consents
        self._ledger = ledger
        self._issuer = settings.iua_token_issuer
        self._audience = settings.iua_token_audience
        self._ttl = settings.iua_token_ttl_seconds
        self._code_ttl = settings.iua_code_ttl_seconds
        self._max_id_token_age = settings.iua_max_id_token_age_seconds
        self._home_community = f"urn:oid:{settings.iua_home_community_oid}"
        self._require_signatures = settings.iua_require_request_signatures
        self._skew = settings.clock_skew_seconds
        self._clients = {client.client_id: client for client in settings.iua_clients}
        self._client_keys = {
            client.client_id: load_public_key(client.public_key_pem)
            for client in settings.iua_clients
            if client.public_key_pem
        }
        #: issuer → verifier with ``verify_presented_id_token`` (SwissIdClient).
        self._verifiers = identity_verifiers or {}
        #: issuer → AssurancePolicy of that provider.
        self._policies = assurance_policies or {}

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def audience(self) -> str:
        return self._audience

    def jwks(self) -> dict[str, Any]:
        return self._key.jwks()

    # -- ITI-103 --------------------------------------------------------------

    def metadata(self, base_url: str) -> dict[str, Any]:
        base = base_url.rstrip("/")
        return {
            "issuer": self._issuer,
            "authorization_endpoint": f"{base}/iua/authorize",
            "token_endpoint": f"{base}/iua/token",
            "jwks_uri": f"{base}/iua/jwks.json",
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256", "ES256"],
            "scopes_supported": ["openid", "purpose_of_use=*", "subject_role=*"],
            "response_types_supported": ["code"],
            "grant_types_supported": [
                GRANT_CLIENT_CREDENTIALS,
                GRANT_AUTHORIZATION_CODE,
                GRANT_JWT_BEARER,
            ],
            "code_challenge_methods_supported": ["S256"],
            "capabilities": [
                "client-confidential-symmetric",
                "sso-openid-connect",
            ],
            "access_token_format": [JWT_TOKEN_TYPE],
        }

    # -- ITI-71, step 1: the authorisation request ----------------------------

    def authorize(
        self,
        session: Session,
        actor: ActorContext,
        params: dict[str, str],
        *,
        session_person_uid: str | None,
    ) -> str:
        """Validate an authorisation request and return the redirect URL
        carrying the code. Raises :class:`IuaError` — which must *not* be
        turned into a redirect: an unverified redirect URI is exactly what an
        open-redirect attack needs."""
        try:
            client = self._clients.get(params.get("client_id", ""))
            if client is None:
                _refuse("unknown client_id", "invalid_client")
            if GRANT_AUTHORIZATION_CODE not in client.grant_types:
                _refuse("client may not use the code flow", "unauthorized_client")
            redirect_uri = params.get("redirect_uri", "")
            if redirect_uri not in client.redirect_uris:
                _refuse("redirect_uri is not registered", "invalid_request")
            if params.get("response_type") != "code":
                _malformed("response_type must be code")
            state = params.get("state", "")
            if not state:
                _malformed("state is required")
            # PKCE is optional in the guide but the token request's
            # code_verifier is required, so it is required here too.
            challenge = params.get("code_challenge", "")
            if params.get("code_challenge_method") != "S256" or not challenge:
                _malformed("PKCE with S256 is required")
            if (rtt := params.get("requested_token_type")) and rtt != JWT_TOKEN_TYPE:
                _malformed("only JWT access tokens are issued")
            scope = parse_scope(params.get("scope", ""))
            if scope.launch:
                _refuse("SMART on FHIR launch is not supported", "invalid_scope")
            spid = (
                parse_person_id(params["person_id"])
                if params.get("person_id")
                else None
            )
            if params.get("principal_id") or params.get("group_id"):
                _refuse("the assistant role is not supported", "invalid_scope")

            now = utcnow()
            jti = new_uid("iua")
            payload = {
                "jti": jti,
                "cid": client.client_id,
                "ru": redirect_uri,
                "cc": challenge,
                "sc": scope.text,
                "pid": spid,
                "uid": session_person_uid,
                "exp": int((now + timedelta(seconds=self._code_ttl)).timestamp()),
            }
            code = self._keyring.encrypt(
                KeyPurpose.IUA_AUTHORIZATION_CODE,
                json.dumps(payload, separators=(",", ":")).encode(),
                aad=f"iua-code|{client.client_id}".encode(),
            )
            session.add(
                IssuedToken(
                    jti=jti,
                    kind=KIND_CODE,
                    subject_uid=session_person_uid or "-",
                    issued_at=now,
                    expires_at=now + timedelta(seconds=self._code_ttl),
                    max_uses=1,
                    key_id=f"{KeyPurpose.IUA_AUTHORIZATION_CODE.value}",
                    algorithm="A256GCM",
                )
            )
            session.flush()
        except IuaError as error:
            self._record_refusal(session, actor, params.get("client_id"), error)
            raise
        separator = "&" if "?" in redirect_uri else "?"
        from urllib.parse import quote

        return (
            f"{redirect_uri}{separator}code={quote(code, safe='')}"
            f"&state={quote(state, safe='')}"
        )

    # -- ITI-71, step 2: the token request -------------------------------------

    def token(
        self, session: Session, actor: ActorContext, request: TokenRequest
    ) -> dict[str, Any]:
        client_id = request.form.get("client_id")
        try:
            client = self._authenticate_client(request)
            client_id = client.client_id
            grant = request.form.get("grant_type", "")
            if grant not in (
                GRANT_CLIENT_CREDENTIALS,
                GRANT_AUTHORIZATION_CODE,
                GRANT_JWT_BEARER,
            ):
                raise IuaError(400, "unsupported_grant_type", f"grant {grant!r}")
            if grant not in client.grant_types:
                _refuse(
                    "grant type not registered for this client", "unauthorized_client"
                )
            rtt = request.form.get("requested_token_type") or request.form.get(
                "requested-token-type"
            )
            if rtt and rtt != JWT_TOKEN_TYPE:
                _malformed("only JWT access tokens are issued")
            if grant == GRANT_CLIENT_CREDENTIALS:
                subject = self._technical_user(session, client, request.form)
            elif grant == GRANT_AUTHORIZATION_CODE:
                subject = self._redeem_code(session, client, request.form)
            else:
                subject = self._jwt_bearer(session, client, request.form)
            return self._issue(session, actor, client, subject)
        except IuaError as error:
            self._record_refusal(session, actor, client_id, error)
            raise

    def _authenticate_client(self, request: TokenRequest) -> IuaClientSettings:
        import base64
        from urllib.parse import unquote_plus

        form = request.form
        authorization = request.headers.get("authorization", "")
        if authorization[:6].lower() == "basic ":
            try:
                decoded = base64.b64decode(authorization[6:].strip(), validate=True)
                client_id, colon, secret = decoded.decode("utf-8").partition(":")
            except (ValueError, UnicodeDecodeError):
                _refuse("malformed basic credentials", "invalid_client")
            if not colon:
                _refuse("malformed basic credentials", "invalid_client")
            # RFC 6749 §2.3.1: both halves are form-urlencoded.
            client_id, secret = unquote_plus(client_id), unquote_plus(secret)
            if form.get("client_id") and form["client_id"] != client_id:
                _refuse(
                    "client_id in the body differs from the header", "invalid_client"
                )
        elif form.get("client_secret"):
            client_id, secret = form.get("client_id", ""), form["client_secret"]
        else:
            _refuse("no client authentication", "invalid_client")

        client = self._clients.get(client_id)
        presented = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        # Compare even for an unknown client, so timing does not reveal
        # which client ids are registered.
        expected = client.client_secret_sha256 if client else "0" * 64
        if not constant_time_equals(presented, expected) or client is None:
            _refuse("client authentication failed", "invalid_client")

        key = self._client_keys.get(client.client_id)
        if key is None:
            if self._require_signatures:
                _refuse("no request-signing key is registered", "invalid_client")
        else:
            try:
                verify_request(
                    public_key=key,
                    method=request.method,
                    target_uri=request.target_uri,
                    headers=request.headers,
                    body=request.body,
                    expected_keyid=client.public_key_id or None,
                    skew=self._skew,
                )
            except SignatureError as exc:
                _refuse(f"request signature: {exc}", "invalid_client")
        return client

    # -- the three ways to identify the subject --------------------------------

    def _technical_user(
        self, session: Session, client: IuaClientSettings, form: dict[str, str]
    ) -> _Subject:
        scope = parse_scope(form.get("scope", ""))
        if scope.role is not Role.TECHNICAL_USER or (
            scope.purpose is not PurposeOfUse.AUTOMATIC
        ):
            _refuse(
                "client credentials require subject_role TCU and purpose AUTO",
                "invalid_scope",
            )
        gln = form.get("principal_id", "")
        if not gln or not constant_time_equals(gln, client.technical_user_gln):
            _refuse("principal_id is not the GLN registered for this client")
        person = self._professional_by_gln(session, gln)
        spid = parse_person_id(form["person_id"]) if form.get("person_id") else None
        return _Subject(
            person=person,
            role=Role.TECHNICAL_USER,
            purpose=PurposeOfUse.AUTOMATIC,
            spid=spid,
            scope=scope,
            gln=gln,
            principal_name=(form.get("principal") or "")[:200] or None,
            via=GRANT_CLIENT_CREDENTIALS,
        )

    def _redeem_code(
        self, session: Session, client: IuaClientSettings, form: dict[str, str]
    ) -> _Subject:
        try:
            payload = json.loads(
                self._keyring.decrypt(
                    form.get("code", ""), aad=f"iua-code|{client.client_id}".encode()
                )
            )
        except (CryptoError, ValueError):
            # Also the answer for a code issued to another client: the AAD
            # binds it, so it does not decrypt.
            _refuse("authorisation code is invalid")
        now = utcnow()
        record = session.get(IssuedToken, payload.get("jti", ""))
        if record is None or record.kind != KIND_CODE:
            _refuse("authorisation code is not registered")
        if record.use_count >= 1 or record.revoked_at is not None:
            # RFC 6749 §4.1.2: a code used twice was stolen, so whatever was
            # issued from it the first time is revoked too.
            self._revoke_issued_from(session, record.jti, now)
            _refuse("authorisation code was already used")
        record.use_count += 1
        record.last_used_at = now
        if now >= record.expires_at or time.time() >= payload.get("exp", 0):
            _refuse("authorisation code has expired")
        if form.get("redirect_uri") != payload["ru"]:
            _refuse("redirect_uri does not match the authorisation request")
        verifier = form.get("code_verifier", "")
        if not verifier or not constant_time_equals(
            b64u(sha256(verifier.encode("ascii", "replace"))), payload["cc"]
        ):
            _refuse("PKCE verification failed")

        if payload.get("uid"):
            person = session.get(Person, payload["uid"])
            via = "session"
        else:
            if form.get("client_assertion_type") != JWT_ASSERTION_TYPE:
                _refuse("the user's identity token is required", "invalid_request")
            person = self._person_from_id_token(
                session, client, form.get("client_assertion", "")
            )
            via = "id-token"
        if person is None:
            _refuse("the user no longer exists")
        return self._subject_for_user(
            session,
            person,
            parse_scope(payload["sc"]),
            payload.get("pid"),
            code_jti=record.jti,
            via=via,
        )

    def _jwt_bearer(
        self, session: Session, client: IuaClientSettings, form: dict[str, str]
    ) -> _Subject:
        person = self._person_from_id_token(session, client, form.get("assertion", ""))
        scope = parse_scope(form.get("scope", ""))
        if scope.launch:
            _refuse("SMART on FHIR launch is not supported", "invalid_scope")
        spid = parse_person_id(form["person_id"]) if form.get("person_id") else None
        return self._subject_for_user(
            session, person, scope, spid, via=GRANT_JWT_BEARER
        )

    def _person_from_id_token(
        self, session: Session, client: IuaClientSettings, id_token: str
    ) -> Person:
        if not id_token:
            _refuse("the user's identity token is required", "invalid_request")
        try:
            unverified = json.loads(b64u_decode(id_token.split(".")[1]))
            issuer = unverified["iss"]
        except (CryptoError, ValueError, IndexError, KeyError, TypeError):
            _refuse("identity token is malformed")
        verifier = self._verifiers.get(issuer)
        if verifier is None:
            _refuse("identity token is from an unknown provider")
        try:
            claims = verifier.verify_presented_id_token(
                id_token,
                audiences=tuple(client.idp_client_ids),
                max_age=self._max_id_token_age,
            )
        except OidcError as exc:
            _refuse(f"identity token: {exc}")
        account = (
            session.execute(
                select(IdentityAccount).where(
                    IdentityAccount.issuer == issuer,
                    IdentityAccount.subject == claims["sub"],
                )
            )
            .scalars()
            .first()
        )
        if account is None or account.status != AccountStatus.ACTIVE.value:
            _refuse("no active account is linked to this identity")
        person = session.get(Person, account.person_uid)
        if person is None:
            _refuse("the account's person no longer exists")
        policy = self._policies.get(issuer)
        professional = self._persons.has_role(
            session, person.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        )
        acr = claims.get("acr")
        if policy is None:
            _refuse("no assurance policy for this provider")
        refusal = policy.refusal(acr, professional=professional)
        if refusal:
            _refuse(refusal)
        # No emailed code can be added on this path, so the provider itself
        # must have asserted two factors.
        if not policy.satisfies_second_factor(acr):
            _refuse(f"level of assurance {acr!r} does not include a second factor")
        return person

    def _subject_for_user(
        self,
        session: Session,
        person: Person,
        scope: RequestedScope,
        spid: str | None,
        *,
        code_jti: str | None = None,
        via: str,
    ) -> _Subject:
        role, purpose = scope.role, scope.purpose
        if role in (Role.ASSISTANT, Role.REPRESENTATIVE):
            _refuse(f"subject_role {role} is not supported", "invalid_scope")
        if role is Role.TECHNICAL_USER:
            _refuse("TCU is only for the client credentials grant", "invalid_scope")
        if spid is not None and (role is None or purpose is None):
            _refuse(
                "an extended token needs subject_role and purpose_of_use",
                "invalid_scope",
            )
        credential = self._persons.active_credential(session, person.uid)
        if role is None:
            role = (
                Role.HEALTHCARE_PROFESSIONAL if credential is not None else Role.PATIENT
            )
        if purpose is not None and (role, purpose) not in _PURPOSES:
            _refuse(
                f"purpose {purpose} is not allowed for role {role}", "invalid_scope"
            )
        gln = None
        if role is Role.HEALTHCARE_PROFESSIONAL:
            if credential is None or not self._persons.has_role(
                session, person.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
            ):
                _refuse("the user holds no live healthcare-professional licence")
            gln = credential.gln
        else:
            if not person.spid or not self._persons.has_role(
                session, person.uid, PersonRoleKind.PATIENT
            ):
                _refuse("the user is not a patient with an EPR-SPID")
            if spid is not None and spid != person.spid:
                # Representatives are not supported, so a patient reaches
                # exactly one record: their own.
                _refuse("a patient may only request access to their own record")
        return _Subject(
            person=person,
            role=role,
            purpose=purpose,
            spid=spid,
            scope=scope,
            gln=gln,
            code_jti=code_jti,
            via=via,
        )

    # -- issuing ----------------------------------------------------------------

    def _issue(
        self,
        session: Session,
        actor: ActorContext,
        client: IuaClientSettings,
        subject: _Subject,
    ) -> dict[str, Any]:
        person = subject.person
        if person.status != PersonStatus.ACTIVE.value:
            _refuse("the user is not active")
        now = utcnow()
        dossier_uid = None
        if subject.spid is not None:
            patient, dossier = self._record_for(session, subject.spid)
            decision = self._decide(
                session,
                person=person,
                role=subject.role,
                purpose=subject.purpose,
                patient_uid=patient.uid,
                now=now,
            )
            if not decision.allowed:
                # Refused now rather than at first use: a token that could
                # never be used would only mislead the client.
                _refuse(f"access policy: {decision.reason}", "access_denied")
            dossier_uid = dossier.uid

        extended = subject.spid is not None
        issued = int(now.timestamp())
        expires = issued + self._ttl
        jti = new_uid("iua")
        view = self._persons.view(session, person)
        subject_name = (
            " ".join(part for part in (view.given_name, view.family_name) if part)
            or person.uid
        )
        ihe_iua: dict[str, Any] = {
            "subject_name": subject_name,
            "home_community_id": self._home_community,
        }
        if subject.role is Role.TECHNICAL_USER:
            ihe_iua["subject_name"] = client.name or client.client_id
        if subject.purpose is not None:
            ihe_iua["purpose_of_use"] = {
                "system": PURPOSE_OF_USE_SYSTEM,
                "code": subject.purpose.value,
            }
        ihe_iua["subject_role"] = {"system": ROLE_SYSTEM, "code": subject.role.value}
        if extended:
            ihe_iua["person_id"] = format_person_id(subject.spid)
        if subject.role is Role.PATIENT:
            ch_epr = {"user_id": person.spid, "user_id_qualifier": QUALIFIER_EPR_SPID}
        else:
            ch_epr = {"user_id": subject.gln, "user_id_qualifier": QUALIFIER_GLN}
        extensions: dict[str, Any] = {"ihe_iua": ihe_iua, "ch_epr": ch_epr}
        if subject.role is Role.TECHNICAL_USER:
            extensions["ch_delegation"] = {
                "principal": subject.principal_name or subject_name,
                "principal_id": subject.gln,
            }
        claims = {
            "iss": self._issuer,
            "sub": (
                client.client_id if subject.role is Role.TECHNICAL_USER else person.uid
            ),
            "aud": self._audience,
            "iat": issued,
            "nbf": issued,
            "exp": expires,
            "jti": jti,
            "client_id": client.client_id,
            "scope": subject.scope.text,
            "extensions": extensions,
        }
        token = self._key.sign(claims)

        session.add(
            IssuedToken(
                jti=jti,
                kind=KIND_EXTENDED if extended else KIND_BASIC,
                subject_uid=person.uid,
                dossier_uid=dossier_uid,
                issued_at=now,
                expires_at=now + timedelta(seconds=self._ttl),
                parent_jti=subject.code_jti,
                key_id=self._key.key_id[:48],
                algorithm=self._key.algorithm,
            )
        )
        session.flush()
        self._ledger.append(
            session,
            actor=ActorContext(
                actor_uid=person.uid,
                actor_kind="iua-client",
                purpose=subject.purpose.value if subject.purpose else None,
                token_jti=jti,
                request_id=actor.request_id,
                client_ip_hash=actor.client_ip_hash,
                user_agent=actor.user_agent,
            ),
            action=AuditAction.TOKEN_ISSUED,
            resource_type="issued_token",
            resource_uid=jti,
            dossier_uid=dossier_uid,
            detail={
                "kind": KIND_EXTENDED if extended else KIND_BASIC,
                "client_id": client.client_id,
                "role": subject.role.value,
                "purpose_of_use": subject.purpose.value if subject.purpose else None,
                "via": subject.via,
                "expires_in": self._ttl,
            },
        )
        return {
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": self._ttl,
            "scope": subject.scope.text,
            "issued_token_type": JWT_TOKEN_TYPE,
        }

    # -- ITI-72: the resource server --------------------------------------------

    def authorize_request(
        self,
        session: Session,
        token: str,
        *,
        required_scope: Scope,
        extended: bool,
        request_context: ActorContext,
    ) -> IuaAccess:
        """Verify an incorporated access token and authorise one request."""
        base = request_context
        try:
            claims = self._verify_claims(self._key.verify(token))
        except IuaError as error:
            self._reject(session, base, None, error.reason)

        jti = claims["jti"]
        extensions = claims.get("extensions") or {}
        ihe_iua = extensions.get("ihe_iua") or {}
        ch_epr = extensions.get("ch_epr") or {}
        now = utcnow()

        record = session.get(IssuedToken, jti)
        if record is None or record.kind not in (KIND_BASIC, KIND_EXTENDED):
            self._reject(session, base, jti, "token is not registered")
        if not record.is_live(now):
            self._reject(session, base, jti, "token is revoked")

        try:
            role = Role(_coded(ihe_iua.get("subject_role"), (ROLE_SYSTEM,)))
            purpose_code = ihe_iua.get("purpose_of_use")
            purpose = (
                PurposeOfUse(_coded(purpose_code, (PURPOSE_OF_USE_SYSTEM,)))
                if purpose_code is not None
                else None
            )
            spid = (
                parse_person_id(ihe_iua["person_id"])
                if ihe_iua.get("person_id")
                else None
            )
        except (ValueError, IuaError) as exc:
            self._reject(session, base, jti, f"malformed IUA claims: {exc}")

        person = self._user_of(session, role, ch_epr, extensions)
        if person is None or person.uid != record.subject_uid:
            self._reject(session, base, jti, "the token's user cannot be resolved")
        if person.status != PersonStatus.ACTIVE.value:
            self._reject(session, base, jti, "the user is not active")
        credential = self._persons.active_credential(session, person.uid)
        internal_purpose = _PURPOSES.get((role, purpose)) if purpose else None
        actor = ActorContext(
            actor_uid=person.uid,
            actor_kind="iua-technical-user" if role is Role.TECHNICAL_USER else "iua",
            organization_uid=credential.organization_uid if credential else None,
            purpose=internal_purpose.value if internal_purpose else None,
            token_jti=jti,
            request_id=base.request_id,
            client_ip_hash=base.client_ip_hash,
            user_agent=base.user_agent,
        )

        scopes = set(BASIC_SCOPES)
        dossier_uid = patient_uid = None
        max_level = Confidentiality.NORMAL
        if spid is None:
            if extended:
                self._reject(session, actor, jti, "a basic token cannot reach a record")
            if role is Role.HEALTHCARE_PROFESSIONAL and credential is None:
                self._reject(session, actor, jti, "licence is no longer live")
        else:
            if purpose is None or internal_purpose is None:
                self._reject(session, actor, jti, "role and purpose do not combine")
            try:
                patient, dossier = self._record_for(session, spid)
            except IuaError as error:
                self._reject(session, actor, jti, error.reason)
            if record.dossier_uid != dossier.uid:
                self._reject(session, actor, jti, "token names another record")
            decision = self._decide(
                session,
                person=person,
                role=role,
                purpose=purpose,
                patient_uid=patient.uid,
                now=now,
            )
            if not decision.allowed:
                self._reject(session, actor, jti, decision.reason)
            scopes |= ROLE_SCOPES[role]
            dossier_uid, patient_uid = dossier.uid, patient.uid
            max_level = decision.max_level
        if required_scope not in scopes:
            self._reject(
                session, actor, jti, f"{role} may not use {required_scope.value}"
            )

        record.use_count += 1
        record.last_used_at = now
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.TOKEN_USED,
            resource_type="issued_token",
            resource_uid=jti,
            dossier_uid=dossier_uid,
            detail={
                "scope": required_scope.value,
                "role": role.value,
                "effective_level": max_level.value,
                "use_count": record.use_count,
            },
        )
        if internal_purpose is Purpose.EMERGENCY:
            self._ledger.append(
                session,
                actor=actor,
                action=AuditAction.EMERGENCY_ACCESS,
                resource_type="dossier",
                resource_uid=dossier_uid,
                dossier_uid=dossier_uid,
                detail={"via": "iua", "notify_patient": True},
            )
        session.flush()
        return IuaAccess(
            jti=jti,
            subject_uid=person.uid,
            role=role,
            purpose=internal_purpose,
            dossier_uid=dossier_uid,
            patient_uid=patient_uid,
            max_level=max_level,
            scopes=frozenset(scopes),
            actor=actor,
            extended=spid is not None,
        )

    def _verify_claims(self, claims: dict[str, Any]) -> dict[str, Any]:
        now = int(time.time())
        if not constant_time_equals(str(claims.get("iss", "")), self._issuer):
            _refuse("issuer mismatch", "invalid_token")
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self._audience not in audiences:
            _refuse("audience mismatch", "invalid_token")
        try:
            issued, not_before, expires = (
                int(claims["iat"]),
                int(claims.get("nbf", claims["iat"])),
                int(claims["exp"]),
            )
        except (KeyError, TypeError, ValueError):
            _refuse("token times are missing", "invalid_token")
        if now + self._skew < not_before:
            _refuse("token is not valid yet", "invalid_token")
        if now - self._skew >= expires:
            _refuse("token has expired", "invalid_token")
        if expires - issued > self._ttl:
            _refuse("token lifetime exceeds policy", "invalid_token")
        if not isinstance(claims.get("jti"), str) or not claims["jti"]:
            _refuse("token has no jti", "invalid_token")
        return claims

    # -- shared -----------------------------------------------------------------

    def _user_of(
        self,
        session: Session,
        role: Role,
        ch_epr: dict[str, Any],
        extensions: dict[str, Any],
    ) -> Person | None:
        user_id = ch_epr.get("user_id")
        qualifier = ch_epr.get("user_id_qualifier")
        if not isinstance(user_id, str):
            return None
        if role is Role.PATIENT:
            if qualifier != QUALIFIER_EPR_SPID:
                return None
            return self._persons.find_by_spid(session, user_id)
        if qualifier != QUALIFIER_GLN:
            return None
        if role is Role.TECHNICAL_USER:
            delegation = extensions.get("ch_delegation") or {}
            if delegation.get("principal_id") != user_id:
                return None
        credential = self._persons.find_by_gln(session, user_id)
        if credential is None:
            return None
        live = self._persons.active_credential(session, credential.person_uid)
        # The licence behind the GLN has to be the one that is live today.
        if live is None or live.gln != user_id:
            return None
        return session.get(Person, credential.person_uid)

    def _professional_by_gln(self, session: Session, gln: str) -> Person:
        credential = self._persons.find_by_gln(session, gln)
        if credential is None:
            _refuse("no professional is registered under that GLN")
        live = self._persons.active_credential(session, credential.person_uid)
        if live is None or live.gln != gln:
            _refuse("the professional's licence is not live")
        person = session.get(Person, credential.person_uid)
        if person is None or not self._persons.has_role(
            session, person.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        ):
            _refuse("the principal holds no healthcare-professional role")
        return person

    def _record_for(self, session: Session, spid: str) -> tuple[Person, Dossier]:
        patient = self._persons.find_by_spid(session, spid)
        if patient is None or not self._persons.has_role(
            session, patient.uid, PersonRoleKind.PATIENT
        ):
            _refuse("no patient with that EPR-SPID", "access_denied")
        dossier = (
            session.execute(select(Dossier).where(Dossier.patient_uid == patient.uid))
            .scalars()
            .first()
        )
        if dossier is None or dossier.status != DossierStatus.ACTIVE.value:
            _refuse("the patient has no active record", "access_denied")
        return patient, dossier

    def _decide(
        self,
        session: Session,
        *,
        person: Person,
        role: Role,
        purpose: PurposeOfUse | None,
        patient_uid: str,
        now: datetime,
    ):
        """The consent decision — the CH:ADR question, answered locally."""
        internal = _PURPOSES[(role, purpose)]
        roles = frozenset(
            PersonRoleKind(r.role)
            for r in self._persons.roles(session, person.uid)
            if r.is_live(now)
        )
        credential = self._persons.active_credential(session, person.uid)
        return evaluate_policy(
            self._consents.snapshot_for(session, patient_uid),
            requester_uid=person.uid,
            requester_roles=roles,
            organization_uid=credential.organization_uid if credential else None,
            purpose=internal,
            now=now,
        )

    def _revoke_issued_from(self, session: Session, code_jti: str, now: datetime):
        for token in session.execute(
            select(IssuedToken).where(
                IssuedToken.parent_jti == code_jti, IssuedToken.revoked_at.is_(None)
            )
        ).scalars():
            token.revoked_at = now
            token.revocation_reason = "authorisation code replayed"

    def _record_refusal(
        self,
        session: Session,
        actor: ActorContext,
        client_id: str | None,
        error: IuaError,
    ) -> None:
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.ACCESS_DENIED,
            resource_type="iua_authorization",
            outcome=AuditOutcome.DENIED,
            detail={
                "client_id": (client_id or "")[:128],
                "error": error.error,
                "reason": error.reason[:200],
            },
        )
        commit_security_event(session)

    def _reject(
        self, session: Session, actor: ActorContext, jti: str | None, reason: str
    ) -> NoReturn:
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.TOKEN_REJECTED,
            resource_type="issued_token",
            resource_uid=jti,
            outcome=AuditOutcome.DENIED,
            detail={"reason": reason[:200], "kind": "iua"},
        )
        commit_security_event(session)
        raise IuaError(401, "invalid_token", reason)


def _coded(value: Any, systems: tuple[str, ...]) -> str:
    if not isinstance(value, dict):
        raise ValueError("coded claim is not an object")
    if value.get("system") not in systems:
        raise ValueError("coded claim uses an unknown system")
    code = value.get("code")
    if not isinstance(code, str):
        raise ValueError("coded claim has no code")
    return code


def new_client_secret() -> tuple[str, str]:
    """A fresh client secret and the hash that goes into the configuration."""
    secret = secrets.token_urlsafe(32)
    return secret, hashlib.sha256(secret.encode("utf-8")).hexdigest()
