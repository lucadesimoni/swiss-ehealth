# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Capability tokens.

A token here is not an identity assertion — it is a *capability*: it names
exactly one dossier, one purpose, one confidentiality ceiling and an explicit
list of scopes, and it expires in minutes. A stolen token therefore buys an
attacker one narrow thing for a short time, rather than everything the holder
could ever do.

Wire format (three base64url segments, dot-separated, JWT-shaped but with a
strict, closed header)::

    base64url(header) "." base64url(payload) "." base64url(signature)

Deviations from stock JWT, all deliberate:

* ``alg`` is validated against a registry and ``none`` does not exist, so the
  classic algorithm-confusion attack has no surface.
* The key id carries a version, so rotation needs no coordination.
* Every token has a ``jti`` registered in the database. Bearer tokens that
  cannot be revoked have no place in a health record.
* ``dlg`` records the delegation chain, so a visitor token issued off a
  patient's authority still says who ultimately authorised it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from ehealth.security.crypto import (
    SIGNATURE_ALGORITHMS,
    CryptoError,
    KeyPurpose,
    KeyRing,
    b64u,
    b64u_decode,
    canonical_json,
    constant_time_equals,
    sha256,
)

TOKEN_VERSION = 1


class Scope(StrEnum):
    """The complete set of things a token can authorise.

    Deliberately coarse-grained and closed: an open-ended scope string would
    make it impossible to answer "what can this token do" by inspection.
    """

    DOSSIER_READ = "dossier:read"
    DOSSIER_WRITE = "dossier:write"
    DOCUMENT_READ = "document:read"
    DOCUMENT_WRITE = "document:write"
    MEDICATION_READ = "medication:read"
    MEDICATION_WRITE = "medication:write"
    AUDIT_READ = "audit:read"
    CONSENT_READ = "consent:read"
    CONSENT_WRITE = "consent:write"
    GRANT_MANAGE = "grant:manage"
    PERSON_READ = "person:read"
    PERSON_WRITE = "person:write"
    ADMIN = "admin"

    @classmethod
    def parse_all(cls, values: list[str]) -> list[Scope]:
        out = []
        for value in values:
            try:
                out.append(cls(value))
            except ValueError:
                raise TokenError(f"unknown scope {value!r}") from None
        return out


#: Scopes a visitor token may ever carry, whatever the grant says. A second
#: ceiling below consent, so a mis-issued grant cannot hand a visitor write
#: access to a clinical record.
VISITOR_SCOPE_CEILING = frozenset(
    {Scope.DOSSIER_READ, Scope.DOCUMENT_READ, Scope.MEDICATION_READ}
)


class TokenError(Exception):
    """Verification failed. The message is safe to log, never to return
    verbatim to an unauthenticated caller."""


@dataclass(frozen=True, slots=True)
class Delegation:
    """One hop in the authority chain."""

    from_uid: str
    to_uid: str
    at: str

    def as_dict(self) -> dict[str, str]:
        return {"from": self.from_uid, "to": self.to_uid, "at": self.at}


@dataclass(slots=True)
class TokenClaims:
    jti: str
    kind: str
    issuer: str
    subject_uid: str
    audience: str
    purpose: str
    scopes: list[Scope]
    issued_at: datetime
    expires_at: datetime
    not_before: datetime
    dossier_uid: str | None = None
    grant_uid: str | None = None
    session_uid: str | None = None
    access_level: str = "normal"
    assurance_level: str = "aal2"
    organization_uid: str | None = None
    on_behalf_of_uid: str | None = None
    delegation: list[Delegation] = field(default_factory=list)
    #: Thumbprint of the holder's public key for proof-of-possession binding.
    cnf_jkt: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "v": TOKEN_VERSION,
            "jti": self.jti,
            "typ": self.kind,
            "iss": self.issuer,
            "sub": self.subject_uid,
            "aud": self.audience,
            "pur": self.purpose,
            "scp": sorted(s.value for s in self.scopes),
            "iat": int(self.issued_at.timestamp()),
            "nbf": int(self.not_before.timestamp()),
            "exp": int(self.expires_at.timestamp()),
            "lvl": self.access_level,
            "aal": self.assurance_level,
        }
        # Optional claims are omitted rather than sent as null, so the signed
        # bytes stay minimal and a missing claim is unambiguous.
        for key, value in (
            ("dos", self.dossier_uid),
            ("grt", self.grant_uid),
            ("ses", self.session_uid),
            ("org", self.organization_uid),
            ("obo", self.on_behalf_of_uid),
        ):
            if value is not None:
                payload[key] = value
        if self.delegation:
            payload["dlg"] = [d.as_dict() for d in self.delegation]
        if self.cnf_jkt:
            payload["cnf"] = {"jkt": self.cnf_jkt}
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> TokenClaims:
        try:
            return cls(
                jti=payload["jti"],
                kind=payload["typ"],
                issuer=payload["iss"],
                subject_uid=payload["sub"],
                audience=payload["aud"],
                purpose=payload["pur"],
                scopes=Scope.parse_all(payload["scp"]),
                issued_at=datetime.fromtimestamp(payload["iat"], UTC),
                not_before=datetime.fromtimestamp(payload["nbf"], UTC),
                expires_at=datetime.fromtimestamp(payload["exp"], UTC),
                access_level=payload.get("lvl", "normal"),
                assurance_level=payload.get("aal", "aal1"),
                dossier_uid=payload.get("dos"),
                grant_uid=payload.get("grt"),
                session_uid=payload.get("ses"),
                organization_uid=payload.get("org"),
                on_behalf_of_uid=payload.get("obo"),
                delegation=[
                    Delegation(d["from"], d["to"], d["at"])
                    for d in payload.get("dlg", [])
                ],
                cnf_jkt=(payload.get("cnf") or {}).get("jkt"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise TokenError(f"malformed token payload: {exc}") from exc

    def has_scope(self, scope: Scope) -> bool:
        return scope in self.scopes or Scope.ADMIN in self.scopes


class TokenService:
    """Mints and verifies capability tokens.

    Verification here is *cryptographic and structural only*. Whether the
    token's ``jti`` is still live, and whether the grant behind it still
    exists, is a database question answered in
    :mod:`ehealth.services.access` — separating the two keeps this class
    pure and unit-testable.
    """

    def __init__(
        self,
        keyring: KeyRing,
        *,
        issuer: str,
        audience: str,
        clock_skew_seconds: int = 30,
        max_ttl_seconds: int = 86_400,
    ) -> None:
        self._keyring = keyring
        self._issuer = issuer
        self._audience = audience
        self._skew = timedelta(seconds=clock_skew_seconds)
        self._max_ttl = timedelta(seconds=max_ttl_seconds)

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def signing_kid(self) -> str:
        """Key id that :meth:`issue` will stamp on the next token."""
        return self._keyring.signer(KeyPurpose.TOKEN_SIGNING).kid

    @property
    def signing_algorithm(self) -> str:
        return self._keyring.signer(KeyPurpose.TOKEN_SIGNING).algorithm

    def issue(self, claims: TokenClaims) -> str:
        lifetime = claims.expires_at - claims.issued_at
        if lifetime <= timedelta(0):
            raise TokenError("token would already be expired")
        if lifetime > self._max_ttl:
            raise TokenError(
                f"requested lifetime {lifetime} exceeds the configured maximum"
            )
        signer = self._keyring.signer(KeyPurpose.TOKEN_SIGNING)
        header = {"alg": signer.algorithm, "kid": signer.kid, "typ": "CAP"}
        header_b64 = b64u(canonical_json(header))
        payload_b64 = b64u(canonical_json(claims.to_payload()))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return f"{header_b64}.{payload_b64}.{signer.sign(signing_input)}"

    def verify(
        self,
        token: str,
        *,
        now: datetime | None = None,
        expected_audience: str | None = None,
    ) -> TokenClaims:
        now = now or datetime.now(UTC)
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenError("token must have three segments")
        header_b64, payload_b64, signature = parts

        try:
            header = _decode_json(header_b64)
            payload = _decode_json(payload_b64)
        except CryptoError as exc:
            raise TokenError("token segments are not valid base64url") from exc

        algorithm = header.get("alg")
        registered = SIGNATURE_ALGORITHMS.get(algorithm or "")
        if registered is None or not registered.available:
            raise TokenError(f"unsupported signature algorithm {algorithm!r}")
        if header.get("typ") != "CAP":
            raise TokenError("unexpected token type")

        kid = header.get("kid") or ""
        try:
            purpose_name, version_str = kid.rsplit(".v", 1)
            version = int(version_str)
            purpose = KeyPurpose(purpose_name)
        except ValueError as exc:
            raise TokenError("token key id is invalid") from exc
        if purpose is not KeyPurpose.TOKEN_SIGNING:
            # Key separation is only real if it is checked: a signature from
            # the audit key must not authorise access.
            raise TokenError("token was signed with a non-token key")

        signer = self._keyring.signer(KeyPurpose.TOKEN_SIGNING, version)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        if not signer.verify(signing_input, signature):
            raise TokenError("signature does not verify")

        if payload.get("v") != TOKEN_VERSION:
            raise TokenError("unsupported token version")

        claims = TokenClaims.from_payload(payload)
        if not constant_time_equals(claims.issuer, self._issuer):
            raise TokenError("issuer mismatch")
        expected = expected_audience or self._audience
        if not constant_time_equals(claims.audience, expected):
            raise TokenError("audience mismatch")
        if now + self._skew < claims.not_before:
            raise TokenError("token is not valid yet")
        if now - self._skew >= claims.expires_at:
            raise TokenError("token has expired")
        if claims.expires_at - claims.issued_at > self._max_ttl:
            raise TokenError("token lifetime exceeds policy")
        return claims

    # -- proof of possession ---------------------------------------------

    @staticmethod
    def thumbprint(public_key_b64: str) -> str:
        """Key thumbprint used in the ``cnf`` claim."""
        return b64u(sha256(public_key_b64.encode("ascii")))

    @staticmethod
    def check_holder_binding(
        claims: TokenClaims, presented_key_b64: str | None
    ) -> None:
        """Enforce sender constraint when the token carries one.

        A token minted with ``cnf`` is useless without the matching key, which
        downgrades token theft from "full access" to "needs the private key
        too".
        """
        if claims.cnf_jkt is None:
            return
        if presented_key_b64 is None:
            raise TokenError("token is holder-bound but no key was presented")
        if not constant_time_equals(
            claims.cnf_jkt, TokenService.thumbprint(presented_key_b64)
        ):
            raise TokenError("presented key does not match the token binding")


def _decode_json(segment: str) -> dict[str, Any]:
    import json

    raw = b64u_decode(segment)
    if len(raw) > 8192:
        raise TokenError("token segment is implausibly large")
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise TokenError("token segment is not valid JSON") from exc
    if not isinstance(value, dict):
        raise TokenError("token segment must be a JSON object")
    return value
