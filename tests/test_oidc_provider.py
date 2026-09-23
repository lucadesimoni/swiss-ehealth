# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The real OIDC client against a provider that behaves like one.

The rest of the suite logs in through ``MockIdentityProvider``, which hands
back an identity without any cryptography — useful for exercising the login
state machine, useless as evidence that :class:`SwissIdClient` would accept a
real SwissID or HIN token and refuse a forged one.

:class:`FakeProvider` closes that gap without network access. It serves
discovery and a JWKS over ``httpx.MockTransport``, checks PKCE and the client
authentication at its token endpoint exactly as a conformant provider would
(including verifying our ``private_key_jwt`` assertion with the key we
publish), signs real ID tokens, and can rotate its signing key mid-test.

What this still does not prove: that SwissID's or HIN's *actual* claims,
``acr`` vocabulary and error responses match. That needs their integration
environments; see ``docs/identity-providers.md``.
"""

from __future__ import annotations

import json
import time
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ehealth.security.crypto import b64u, b64u_decode
from ehealth.security.oidc import (
    PRIVATE_KEY_JWT,
    OidcConfig,
    OidcError,
    SwissIdClient,
    load_client_signing_key,
    public_jwk,
)

ISSUER = "https://login.fake-provider.ch"
CLIENT_ID = "dossier-client"
REDIRECT = "https://dossier.example.ch/auth/callback"


def _sign(key: Any, alg: str, signing_input: bytes) -> bytes:
    if alg == "RS256":
        return key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    r, s = decode_dss_signature(key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _jws(key: Any, alg: str, kid: str | None, claims: dict) -> str:
    header = {"alg": alg, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    head = b64u(json.dumps(header).encode())
    body = b64u(json.dumps(claims).encode())
    signature = _sign(key, alg, f"{head}.{body}".encode())
    return f"{head}.{body}.{b64u(signature)}"


class FakeProvider:
    """A conformant-enough OIDC provider, in process."""

    def __init__(self, *, alg: str = "ES256", client_secret: str = "s3cret"):
        self.alg = alg
        self.client_secret = client_secret
        self.client_jwks: dict | None = None  # our registered public key(s)
        self.acr = "loa-3"
        self.issuer = ISSUER
        self.audience: str | list[str] = CLIENT_ID
        self.id_token_ttl = 300
        self.nonce_override: str | None = None
        self.codes: dict[str, dict] = {}
        self.seen_assertion_ids: set[str] = set()
        self.token_requests: list[dict] = []
        self.keys: list[tuple[str, Any]] = []
        self.rotate()

    # -- keys ---------------------------------------------------------------

    def _new_key(self) -> Any:
        if self.alg == "RS256":
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return ec.generate_private_key(ec.SECP256R1())

    def rotate(self) -> str:
        """Publish a new signing key and sign with it from now on."""
        kid = f"k{len(self.keys) + 1}"
        self.keys.append((kid, self._new_key()))
        return kid

    @property
    def signing(self) -> tuple[str, Any]:
        return self.keys[-1]

    def jwks(self) -> dict:
        return {"keys": [public_jwk(key.public_key(), kid) for kid, key in self.keys]}

    # -- the user authenticating ----------------------------------------------

    def authorize(self, authorization_url: str, *, subject: str = "sub-anna") -> str:
        query = {
            k: v[0] for k, v in parse_qs(urlparse(authorization_url).query).items()
        }
        assert query["code_challenge_method"] == "S256"
        code = f"code-{len(self.codes)}"
        self.codes[code] = {
            "challenge": query["code_challenge"],
            "nonce": query["nonce"],
            "redirect_uri": query["redirect_uri"],
            "subject": subject,
            "acr_values": query.get("acr_values"),
        }
        return code

    # -- HTTP -----------------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/jwks",
                },
            )
        if path == "/jwks":
            return httpx.Response(200, json=self.jwks())
        if path == "/token":
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        self.token_requests.append(form)
        if not self._client_authenticated(form):
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self.codes.pop(form.get("code", ""), None)  # single use
        if grant is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        verifier = form.get("code_verifier", "")
        if b64u(sha256(verifier.encode()).digest()) != grant["challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant"})
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant"})

        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": grant["subject"],
            "aud": self.audience,
            "iat": now,
            "exp": now + self.id_token_ttl,
            "nonce": self.nonce_override or grant["nonce"],
            "email": "anna.muster@example.ch",
            "email_verified": True,
            "acr": self.acr,
        }
        kid, key = self.signing
        return httpx.Response(
            200,
            json={"id_token": _jws(key, self.alg, kid, claims), "token_type": "Bearer"},
        )

    def _client_authenticated(self, form: dict) -> bool:
        if "client_assertion" not in form:
            return (
                form.get("client_id") == CLIENT_ID
                and form.get("client_secret") == self.client_secret
            )
        if form.get("client_assertion_type") != (
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ):
            return False
        return self._verify_client_assertion(form["client_assertion"])

    def _verify_client_assertion(self, assertion: str) -> bool:
        head_b64, body_b64, sig_b64 = assertion.split(".")
        header = json.loads(b64u_decode(head_b64))
        claims = json.loads(b64u_decode(body_b64))
        jwk = next(
            k
            for k in (self.client_jwks or {"keys": []})["keys"]
            if k.get("kid") == header.get("kid")
        )
        signing_input = f"{head_b64}.{body_b64}".encode()
        signature = b64u_decode(sig_b64)
        try:
            if jwk["kty"] == "RSA":
                n = int.from_bytes(b64u_decode(jwk["n"]), "big")
                e = int.from_bytes(b64u_decode(jwk["e"]), "big")
                rsa.RSAPublicNumbers(e, n).public_key().verify(
                    signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
                )
            else:
                x = int.from_bytes(b64u_decode(jwk["x"]), "big")
                y = int.from_bytes(b64u_decode(jwk["y"]), "big")
                key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
                der = encode_dss_signature(
                    int.from_bytes(signature[:32], "big"),
                    int.from_bytes(signature[32:], "big"),
                )
                key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return False
        now = int(time.time())
        if claims["iss"] != CLIENT_ID or claims["sub"] != CLIENT_ID:
            return False
        if claims["aud"] != f"{ISSUER}/token":
            return False
        if claims["exp"] < now or claims["exp"] - claims["iat"] > 300:
            return False
        if claims["jti"] in self.seen_assertion_ids:
            return False  # replay
        self.seen_assertion_ids.add(claims["jti"])
        return True


def _pem(key: Any) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def make_client(provider: FakeProvider, **overrides) -> SwissIdClient:
    config = OidcConfig(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT,
        client_secret=provider.client_secret,
        acr_values=("loa-3",),
        **overrides,
    )
    http = httpx.Client(transport=httpx.MockTransport(provider.handler))
    return SwissIdClient(config, http=http)


def login(client: SwissIdClient, provider: FakeProvider, **authorize_kwargs):
    request = client.start()
    code = provider.authorize(request.url, **authorize_kwargs)
    return client.complete(
        code=code, code_verifier=request.code_verifier, nonce=request.nonce
    )


@pytest.fixture(params=["ES256", "RS256"])
def provider(request) -> FakeProvider:
    return FakeProvider(alg=request.param)


class TestTheFlowAgainstARealisticProvider:
    def test_a_full_login_verifies_and_carries_the_acr(self, provider):
        identity = login(make_client(provider), provider)
        assert identity.issuer == ISSUER
        assert identity.subject == "sub-anna"
        assert identity.acr == "loa-3"

    def test_the_requested_level_reaches_the_provider(self, provider):
        client = make_client(provider)
        request = client.start()
        query = parse_qs(urlparse(request.url).query)
        assert query["acr_values"] == ["loa-3"]
        assert query["code_challenge_method"] == ["S256"]

    def test_an_authorisation_code_works_once(self, provider):
        client = make_client(provider)
        request = client.start()
        code = provider.authorize(request.url)
        client.complete(
            code=code, code_verifier=request.code_verifier, nonce=request.nonce
        )
        with pytest.raises(OidcError, match="rejected the authorisation code"):
            client.complete(
                code=code, code_verifier=request.code_verifier, nonce=request.nonce
            )

    def test_a_wrong_pkce_verifier_is_refused_by_the_provider(self, provider):
        client = make_client(provider)
        request = client.start()
        code = provider.authorize(request.url)
        with pytest.raises(OidcError, match="rejected the authorisation code"):
            client.complete(code=code, code_verifier="x" * 64, nonce=request.nonce)


class TestKeyRotation:
    def test_a_token_signed_with_a_newly_rotated_key_still_verifies(self, provider):
        """The client caches the JWKS. When the provider rotates, the first
        token under the new key must trigger one refresh — not a lockout of
        every user until someone restarts the service."""
        client = make_client(provider)
        login(client, provider)  # populates the cached JWKS
        provider.rotate()
        identity = login(client, provider)
        assert identity.subject == "sub-anna"

    def test_a_key_the_provider_never_published_is_refused(self, provider):
        client = make_client(provider)
        login(client, provider)
        rogue_kid, rogue_key = "rogue", provider._new_key()
        provider.keys.append((rogue_kid, rogue_key))
        # Sign with the rogue key but withdraw it from the JWKS.
        original_jwks = provider.jwks
        provider.jwks = lambda: {
            "keys": [k for k in original_jwks()["keys"] if k["kid"] != rogue_kid]
        }
        with pytest.raises(OidcError, match="no matching key"):
            login(client, provider)


class TestForgeries:
    """Each of these is a token an attacker could construct. All must fail."""

    def test_a_tampered_payload_is_refused(self, provider):
        client = make_client(provider)
        request = client.start()
        code = provider.authorize(request.url)
        original = provider._token

        def tamper(req):
            response = original(req)
            token = response.json()["id_token"]
            head, body, sig = token.split(".")
            claims = json.loads(b64u_decode(body))
            claims["sub"] = "someone-else"
            forged = f"{head}.{b64u(json.dumps(claims).encode())}.{sig}"
            return httpx.Response(200, json={"id_token": forged})

        provider._token = tamper
        with pytest.raises(OidcError, match="signature does not verify"):
            client.complete(
                code=code, code_verifier=request.code_verifier, nonce=request.nonce
            )

    @pytest.mark.parametrize("alg", ["none", "HS256"])
    def test_unsigned_and_symmetric_tokens_are_refused(self, provider, alg):
        """``HS256`` matters: signed with the client secret, it would let
        anyone holding that secret mint identities."""
        client = make_client(provider)
        request = client.start()
        code = provider.authorize(request.url)
        header = b64u(json.dumps({"alg": alg}).encode())
        body = b64u(json.dumps({"iss": ISSUER, "sub": "x", "aud": CLIENT_ID}).encode())
        provider._token = lambda req: httpx.Response(
            200, json={"id_token": f"{header}.{body}.{b64u(b'sig')}"}
        )
        with pytest.raises(OidcError, match="unacceptable ID token algorithm"):
            client.complete(
                code=code, code_verifier=request.code_verifier, nonce=request.nonce
            )

    def test_a_token_from_another_issuer_is_refused(self, provider):
        provider.issuer = "https://evil.example"
        with pytest.raises(OidcError, match="issuer mismatch"):
            login(make_client(provider), provider)

    def test_a_token_minted_for_another_client_is_refused(self, provider):
        provider.audience = "someone-elses-client"
        with pytest.raises(OidcError, match="audience mismatch"):
            login(make_client(provider), provider)

    def test_an_expired_token_is_refused(self, provider):
        provider.id_token_ttl = -3600
        with pytest.raises(OidcError, match="expired"):
            login(make_client(provider), provider)

    def test_a_replayed_token_with_another_nonce_is_refused(self, provider):
        provider.nonce_override = "nonce-from-an-earlier-login"
        with pytest.raises(OidcError, match="nonce mismatch"):
            login(make_client(provider), provider)


class TestPrivateKeyJwt:
    @pytest.fixture(params=["ec", "rsa"])
    def client_key(self, request):
        if request.param == "ec":
            return ec.generate_private_key(ec.SECP256R1())
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _client(self, provider, key) -> SwissIdClient:
        client = make_client(
            provider,
            client_auth_method=PRIVATE_KEY_JWT,
            private_key_pem=_pem(key),
            private_key_id="dossier-2026-09",
        )
        provider.client_jwks = client.public_jwks()  # registration with the IdP
        return client

    def test_the_provider_accepts_our_signed_assertion(self, provider, client_key):
        identity = login(self._client(provider, client_key), provider)
        assert identity.subject == "sub-anna"

    def test_no_secret_is_sent(self, provider, client_key):
        login(self._client(provider, client_key), provider)
        sent = provider.token_requests[-1]
        assert "client_secret" not in sent
        assert sent["client_assertion_type"].endswith("jwt-bearer")

    def test_every_assertion_is_fresh(self, provider, client_key):
        """A fixed assertion would be a secret that can be replayed; the
        provider here refuses a reused ``jti``, and two logins must pass."""
        client = self._client(provider, client_key)
        login(client, provider)
        login(client, provider)
        assert len(provider.seen_assertion_ids) == 2

    def test_a_key_the_provider_does_not_know_is_refused(self, provider, client_key):
        client = self._client(provider, client_key)
        provider.client_jwks = {
            "keys": [
                public_jwk(
                    ec.generate_private_key(ec.SECP256R1()).public_key(),
                    "dossier-2026-09",
                )
            ]
        }
        with pytest.raises(OidcError, match="rejected the authorisation code"):
            login(client, provider)

    def test_the_published_jwks_holds_no_private_material(self, provider, client_key):
        jwks = self._client(provider, client_key).public_jwks()
        (key,) = jwks["keys"]
        assert "d" not in key and "p" not in key and "q" not in key
        assert key["kid"] == "dossier-2026-09" and key["use"] == "sig"

    def test_a_secret_based_client_publishes_nothing(self, provider):
        assert make_client(provider).public_jwks() == {"keys": []}


class TestClientKeyValidation:
    def test_a_short_rsa_key_is_refused(self):
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 (the weak key under test)
        with pytest.raises(OidcError, match="at least 2048"):
            load_client_signing_key(_pem(weak))

    def test_an_unsupported_curve_is_refused(self):
        with pytest.raises(OidcError, match=r"RSA .* or EC P-256"):
            load_client_signing_key(_pem(ec.generate_private_key(ec.SECP384R1())))

    def test_garbage_is_refused(self):
        with pytest.raises(OidcError, match="not a readable PEM"):
            load_client_signing_key("not a key")

    def test_private_key_jwt_without_a_key_is_refused_at_construction(self):
        with pytest.raises(OidcError, match="needs a private key"):
            SwissIdClient(
                OidcConfig(
                    issuer=ISSUER,
                    client_id=CLIENT_ID,
                    redirect_uri=REDIRECT,
                    client_auth_method=PRIVATE_KEY_JWT,
                )
            )
