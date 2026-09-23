# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""OpenID Connect client for SwissID, HIN, or any conformant provider.

Implements the authorisation code flow with PKCE and full ID token
verification — signature against the provider's JWKS, issuer, audience,
expiry and nonce. None of that is optional: an ID token accepted without
signature verification is just an attacker-supplied JSON document.

The client authenticates to the provider with either a shared secret
(``client_secret_post``) or a signed assertion (``private_key_jwt``, RFC 7523).
The second is preferred: the private key never leaves this system, so a leaked
configuration file or log line cannot be replayed at the token endpoint, and
rotating it is a key change rather than a secret shared with a third party.

Whether the *level of assurance* in the ID token is good enough is not decided
here — that is policy, and it lives in :mod:`ehealth.services.auth` so it
applies identically to every provider, the mock included.

A :class:`MockIdentityProvider` mirrors the same interface for local
development and tests. It refuses to be constructed in production, so the
"forgot to switch off the fake login" failure is impossible rather than
merely unlikely.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ehealth.security.crypto import CryptoError, b64u, b64u_decode, sha256

#: Signature algorithms we accept on an ID token. ``none`` is absent by
#: construction, and symmetric algorithms are excluded so a leaked client
#: secret cannot be used to forge tokens.
ACCEPTED_ID_TOKEN_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"}
)

DEFAULT_CLOCK_SKEW = 60

#: Lifetime of a ``private_key_jwt`` client assertion. Short on purpose: it is
#: used once, immediately, and a long-lived assertion is a replayable secret.
CLIENT_ASSERTION_TTL_SECONDS = 60

CLIENT_SECRET_POST = "client_secret_post"  # noqa: S105 (a method name, not a secret)
PRIVATE_KEY_JWT = "private_key_jwt"
CLIENT_AUTH_METHODS = frozenset({CLIENT_SECRET_POST, PRIVATE_KEY_JWT})


class OidcError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class OidcConfig:
    issuer: str
    client_id: str
    redirect_uri: str
    client_secret: str = field(default="", repr=False)
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    #: Discovered lazily from ``/.well-known/openid-configuration`` unless set.
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    #: Levels of assurance to *request*, sent as ``acr_values``. A request is
    #: only a request — the provider may answer with less, which is why the
    #: level actually asserted is checked again in the auth service.
    acr_values: tuple[str, ...] = ()
    #: ``client_secret_post`` or ``private_key_jwt``.
    client_auth_method: str = CLIENT_SECRET_POST
    #: PEM-encoded private key for ``private_key_jwt`` (RSA or EC P-256).
    private_key_pem: str = field(default="", repr=False)
    #: Key identifier published alongside the public key, so the provider can
    #: pick the right one during rotation.
    private_key_id: str = ""


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    url: str
    state: str
    nonce: str
    code_verifier: str


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """What the provider asserted about the user."""

    issuer: str
    subject: str
    email: str | None
    email_verified: bool
    given_name: str | None
    family_name: str | None
    acr: str | None
    raw_claims: dict[str, Any]


class IdentityProvider(Protocol):
    def start(self) -> AuthorizationRequest: ...

    def complete(
        self, *, code: str, code_verifier: str, nonce: str
    ) -> VerifiedIdentity: ...


def _pkce_pair() -> tuple[str, str]:
    verifier = b64u(secrets.token_bytes(48))
    challenge = b64u(sha256(verifier.encode("ascii")))
    return verifier, challenge


class SwissIdClient:
    """OIDC relying party."""

    def __init__(
        self,
        config: OidcConfig,
        *,
        http: httpx.Client | None = None,
        clock_skew: int = DEFAULT_CLOCK_SKEW,
    ) -> None:
        if not config.client_id:
            raise OidcError("a client_id is required")
        if config.client_auth_method not in CLIENT_AUTH_METHODS:
            raise OidcError(
                f"unknown client authentication method {config.client_auth_method!r}"
            )
        self._signing_key: Any = None
        if config.client_auth_method == PRIVATE_KEY_JWT:
            if not config.private_key_pem:
                raise OidcError("private_key_jwt needs a private key")
            self._signing_key = load_client_signing_key(config.private_key_pem)
        elif not config.client_secret:
            raise OidcError("client_secret_post needs a client secret")
        self._config = config
        self._http = http or httpx.Client(timeout=10.0)
        self._skew = clock_skew
        self._metadata: dict[str, Any] | None = None
        self._jwks: dict[str, Any] | None = None

    # -- discovery --------------------------------------------------------

    def metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            if self._config.authorization_endpoint and self._config.token_endpoint:
                self._metadata = {
                    "issuer": self._config.issuer,
                    "authorization_endpoint": self._config.authorization_endpoint,
                    "token_endpoint": self._config.token_endpoint,
                    "jwks_uri": self._config.jwks_uri,
                }
            else:
                url = (
                    self._config.issuer.rstrip("/")
                    + "/.well-known/openid-configuration"
                )
                response = self._http.get(url)
                response.raise_for_status()
                document = response.json()
                if document.get("issuer") != self._config.issuer:
                    raise OidcError("discovery document issuer does not match")
                self._metadata = document
        return self._metadata

    def _jwks_keys(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        if self._jwks is None or refresh:
            uri = self.metadata().get("jwks_uri")
            if not uri:
                raise OidcError("provider does not publish a JWKS URI")
            response = self._http.get(uri)
            response.raise_for_status()
            self._jwks = response.json()
        return list((self._jwks or {}).get("keys", []))

    # -- flow -------------------------------------------------------------

    def start(self) -> AuthorizationRequest:
        verifier, challenge = _pkce_pair()
        state = b64u(secrets.token_bytes(24))
        nonce = b64u(secrets.token_bytes(24))
        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": self._config.redirect_uri,
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if self._config.acr_values:
            params["acr_values"] = " ".join(self._config.acr_values)
        endpoint = self.metadata()["authorization_endpoint"]
        return AuthorizationRequest(
            url=f"{endpoint}?{urlencode(params)}",
            state=state,
            nonce=nonce,
            code_verifier=verifier,
        )

    def _client_authentication(self, token_endpoint: str) -> dict[str, str]:
        """The form fields that prove to the provider this is our client."""
        if self._config.client_auth_method == CLIENT_SECRET_POST:
            return {
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
            }
        return {
            "client_id": self._config.client_id,
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": build_client_assertion(
                self._signing_key,
                key_id=self._config.private_key_id,
                client_id=self._config.client_id,
                audience=token_endpoint,
            ),
        }

    def public_jwks(self) -> dict[str, Any]:
        """Our public key as a JWK Set, for registering with the provider.

        Empty under ``client_secret_post``: there is no key to publish.
        """
        if self._signing_key is None:
            return {"keys": []}
        return {
            "keys": [
                public_jwk(self._signing_key.public_key(), self._config.private_key_id)
            ]
        }

    def complete(
        self, *, code: str, code_verifier: str, nonce: str
    ) -> VerifiedIdentity:
        token_endpoint = self.metadata()["token_endpoint"]
        token_response = self._http.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._config.redirect_uri,
                "code_verifier": code_verifier,
                **self._client_authentication(token_endpoint),
            },
            headers={"Accept": "application/json"},
        )
        if token_response.status_code != 200:
            raise OidcError("token endpoint rejected the authorisation code")
        payload = token_response.json()
        id_token = payload.get("id_token")
        if not id_token:
            raise OidcError("token response carried no ID token")
        claims = self.verify_id_token(id_token, nonce=nonce)
        return VerifiedIdentity(
            issuer=claims["iss"],
            subject=claims["sub"],
            email=claims.get("email"),
            email_verified=bool(claims.get("email_verified", False)),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            acr=claims.get("acr"),
            raw_claims=claims,
        )

    # -- ID token verification -------------------------------------------

    def verify_id_token(self, id_token: str, *, nonce: str) -> dict[str, Any]:
        parts = id_token.split(".")
        if len(parts) != 3:
            raise OidcError("ID token is not a compact JWS")
        header_b64, payload_b64, signature_b64 = parts
        try:
            header = json.loads(b64u_decode(header_b64))
            claims = json.loads(b64u_decode(payload_b64))
            signature = b64u_decode(signature_b64)
        except (CryptoError, ValueError) as exc:
            raise OidcError("ID token is malformed") from exc

        algorithm = header.get("alg")
        if algorithm not in ACCEPTED_ID_TOKEN_ALGORITHMS:
            raise OidcError(f"unacceptable ID token algorithm {algorithm!r}")

        key = self._find_key(header.get("kid"), algorithm)
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        if not _verify_jws(key, algorithm, signing_input, signature):
            raise OidcError("ID token signature does not verify")

        now = int(time.time())
        if claims.get("iss") != self._config.issuer:
            raise OidcError("ID token issuer mismatch")
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self._config.client_id not in audiences:
            raise OidcError("ID token audience mismatch")
        if len(audiences) > 1 and claims.get("azp") != self._config.client_id:
            raise OidcError("multi-audience ID token without matching azp")
        if now - self._skew >= int(claims.get("exp", 0)):
            raise OidcError("ID token has expired")
        if int(claims.get("iat", 0)) - self._skew > now:
            raise OidcError("ID token was issued in the future")
        if claims.get("nonce") != nonce:
            raise OidcError("ID token nonce mismatch")
        if not claims.get("sub"):
            raise OidcError("ID token carries no subject")
        return claims

    def _find_key(self, kid: str | None, algorithm: str) -> Any:
        for refresh in (False, True):
            for jwk in self._jwks_keys(refresh=refresh):
                if kid and jwk.get("kid") != kid:
                    continue
                if jwk.get("alg") and jwk["alg"] != algorithm:
                    continue
                return _jwk_to_public_key(jwk)
        raise OidcError("no matching key in the provider JWKS")


# --------------------------------------------------------------------------
# JWKS decoding and JWS verification
# --------------------------------------------------------------------------


def _int_from_b64u(value: str) -> int:
    return int.from_bytes(b64u_decode(value), "big")


def _jwk_to_public_key(jwk: dict[str, Any]) -> Any:
    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(
            e=_int_from_b64u(jwk["e"]), n=_int_from_b64u(jwk["n"])
        ).public_key()
    if kty == "EC":
        curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}
        curve = curves.get(jwk.get("crv", ""))
        if curve is None:
            raise OidcError(f"unsupported EC curve {jwk.get('crv')!r}")
        return ec.EllipticCurvePublicNumbers(
            x=_int_from_b64u(jwk["x"]), y=_int_from_b64u(jwk["y"]), curve=curve
        ).public_key()
    if kty == "OKP" and jwk.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64u_decode(jwk["x"]))
    raise OidcError(f"unsupported key type {kty!r}")


def _verify_jws(
    key: Any, algorithm: str, signing_input: bytes, signature: bytes
) -> bool:
    digests = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
    try:
        if algorithm.startswith("RS"):
            key.verify(
                signature, signing_input, padding.PKCS1v15(), digests[algorithm[2:]]
            )
        elif algorithm.startswith("ES"):
            # JWS uses raw r||s; cryptography expects DER.
            half = len(signature) // 2
            der = encode_dss_signature(
                int.from_bytes(signature[:half], "big"),
                int.from_bytes(signature[half:], "big"),
            )
            key.verify(der, signing_input, ec.ECDSA(digests[algorithm[2:]]))
        elif algorithm == "EdDSA":
            key.verify(signature, signing_input)
        else:  # pragma: no cover - guarded by the allow-list above
            return False
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
    return True


# --------------------------------------------------------------------------
# Client authentication: private_key_jwt (RFC 7523)
# --------------------------------------------------------------------------


def load_client_signing_key(pem: str) -> Any:
    """Load the client's private key. RSA (2048 bit or more) or EC P-256.

    Anything else is refused here rather than at the first login, so a wrong
    key fails the deployment instead of a patient.
    """
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    except (ValueError, TypeError) as exc:
        raise OidcError("client private key is not a readable PEM key") from exc
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise OidcError("client RSA key must be at least 2048 bits")
        return key
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(
        key.curve, ec.SECP256R1
    ):
        return key
    raise OidcError("client key must be RSA (>= 2048 bit) or EC P-256")


def _client_key_algorithm(key: Any) -> str:
    return "RS256" if isinstance(key, rsa.RSAPrivateKey) else "ES256"


def build_client_assertion(
    key: Any,
    *,
    key_id: str,
    client_id: str,
    audience: str,
    now: int | None = None,
) -> str:
    """A signed, single-use JWT proving possession of the client key.

    ``iss`` and ``sub`` are both the client id, ``aud`` is the token endpoint
    (so an assertion captured at one provider is useless at another), and a
    random ``jti`` lets the provider refuse a replay within the short lifetime.
    """
    issued = int(time.time()) if now is None else now
    algorithm = _client_key_algorithm(key)
    header = {"alg": algorithm, "typ": "JWT"}
    if key_id:
        header["kid"] = key_id
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": b64u(secrets.token_bytes(24)),
        "iat": issued,
        "exp": issued + CLIENT_ASSERTION_TTL_SECONDS,
    }
    signing_input = (
        f"{b64u(json.dumps(header, separators=(',', ':')).encode())}."
        f"{b64u(json.dumps(claims, separators=(',', ':')).encode())}"
    ).encode("ascii")
    if algorithm == "RS256":
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:
        # cryptography returns DER; JWS wants the raw 32-byte r || s.
        r, s_value = decode_dss_signature(
            key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        )
        signature = r.to_bytes(32, "big") + s_value.to_bytes(32, "big")
    return f"{signing_input.decode('ascii')}.{b64u(signature)}"


def public_jwk(public_key: Any, key_id: str) -> dict[str, Any]:
    """Serialise a public key as a JWK, for the provider's client registration."""
    if isinstance(public_key, rsa.RSAPublicKey):
        numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "alg": "RS256",
            "n": b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }
    else:
        numbers = public_key.public_numbers()
        jwk = {
            "kty": "EC",
            "alg": "ES256",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32, "big")),
            "y": b64u(numbers.y.to_bytes(32, "big")),
        }
    jwk["use"] = "sig"
    if key_id:
        jwk["kid"] = key_id
    return jwk


# --------------------------------------------------------------------------
# Development provider
# --------------------------------------------------------------------------


class MockIdentityProvider:
    """In-process stand-in for SwissID.

    Issues opaque codes bound to a canned identity. Used by the test suite and
    by ``make run`` so a developer can exercise the whole login path without
    credentials for a real provider.
    """

    def __init__(
        self, *, issuer: str = "https://mock-idp.local", production: bool = False
    ) -> None:
        if production:
            raise OidcError("the mock identity provider must not run in production")
        self._issuer = issuer
        self._pending: dict[str, tuple[str, VerifiedIdentity]] = {}
        self._identities: dict[str, VerifiedIdentity] = {}

    def enrol(
        self,
        subject: str,
        *,
        email: str,
        given_name: str = "Test",
        family_name: str = "Person",
        acr: str = "loa-3",
    ) -> VerifiedIdentity:
        identity = VerifiedIdentity(
            issuer=self._issuer,
            subject=subject,
            email=email,
            email_verified=True,
            given_name=given_name,
            family_name=family_name,
            acr=acr,
            raw_claims={"sub": subject, "email": email, "acr": acr},
        )
        self._identities[subject] = identity
        return identity

    def start(self) -> AuthorizationRequest:
        verifier, challenge = _pkce_pair()
        state = b64u(secrets.token_bytes(24))
        nonce = b64u(secrets.token_bytes(24))
        return AuthorizationRequest(
            url=f"{self._issuer}/authorize?state={state}&code_challenge={challenge}",
            state=state,
            nonce=nonce,
            code_verifier=verifier,
        )

    def authorize(self, subject: str, nonce: str) -> str:
        """Simulate the user authenticating; returns the authorisation code."""
        identity = self._identities.get(subject)
        if identity is None:
            raise OidcError("unknown mock subject")
        code = b64u(secrets.token_bytes(24))
        self._pending[code] = (nonce, identity)
        return code

    def complete(
        self, *, code: str, code_verifier: str, nonce: str
    ) -> VerifiedIdentity:
        entry = self._pending.pop(code, None)  # single use, like the real thing
        if entry is None:
            raise OidcError("unknown or already used authorisation code")
        expected_nonce, identity = entry
        if expected_nonce != nonce:
            raise OidcError("nonce mismatch")
        if not code_verifier:
            raise OidcError("PKCE verifier missing")
        return identity
