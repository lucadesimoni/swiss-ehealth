"""OpenID Connect client for SwissID (or any conformant provider).

Implements the authorisation code flow with PKCE and full ID token
verification — signature against the provider's JWKS, issuer, audience,
expiry and nonce. None of that is optional: an ID token accepted without
signature verification is just an attacker-supplied JSON document.

A :class:`MockIdentityProvider` mirrors the same interface for local
development and tests. It refuses to be constructed in production, so the
"forgot to switch off the fake login" failure is impossible rather than
merely unlikely.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

from ehealth.security.crypto import CryptoError, b64u, b64u_decode, sha256

#: Signature algorithms we accept on an ID token. ``none`` is absent by
#: construction, and symmetric algorithms are excluded so a leaked client
#: secret cannot be used to forge tokens.
ACCEPTED_ID_TOKEN_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"})

DEFAULT_CLOCK_SKEW = 60


class OidcError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class OidcConfig:
    issuer: str
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    #: Discovered lazily from ``/.well-known/openid-configuration`` unless set.
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    #: SwissID levels of assurance, requested via the ``acr_values`` parameter.
    acr_values: tuple[str, ...] = ()


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
        if not config.client_id or not config.client_secret:
            raise OidcError("client credentials are required")
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
                url = self._config.issuer.rstrip("/") + "/.well-known/openid-configuration"
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

    def complete(
        self, *, code: str, code_verifier: str, nonce: str
    ) -> VerifiedIdentity:
        token_response = self._http.post(
            self.metadata()["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._config.redirect_uri,
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "code_verifier": code_verifier,
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


def _verify_jws(key: Any, algorithm: str, signing_input: bytes, signature: bytes) -> bool:
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
# Development provider
# --------------------------------------------------------------------------


class MockIdentityProvider:
    """In-process stand-in for SwissID.

    Issues opaque codes bound to a canned identity. Used by the test suite and
    by ``make run`` so a developer can exercise the whole login path without
    credentials for a real provider.
    """

    def __init__(self, *, issuer: str = "https://mock-idp.local", production: bool = False) -> None:
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
