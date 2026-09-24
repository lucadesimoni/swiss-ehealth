# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""RFC 9421 signatures on IUA token requests, as CH EPR FHIR requires them."""

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ehealth.security.httpsig import (
    SignatureError,
    content_digest,
    load_public_key,
    parse_signature_input,
    sign_request,
    verify_content_digest,
    verify_request,
)

URI = "https://dossier.example.ch/v1/iua/token"
BODY = b"grant_type=client_credentials&principal_id=7601000000002"
AUTH = "Basic " + base64.b64encode(b"archive:secret").decode()


def _keys():
    return {
        "rsa": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ec": ec.generate_private_key(ec.SECP256R1()),
        "ed25519": ed25519.Ed25519PrivateKey.generate(),
    }


KEYS = _keys()


def _public(key):
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return load_public_key(pem)


def _signed(key, *, body=BODY, **kwargs):
    headers = {"authorization": AUTH}
    headers.update(
        {
            k.lower(): v
            for k, v in sign_request(
                private_key=key,
                method="POST",
                target_uri=URI,
                headers=headers,
                body=body,
                keyid="client-key-1",
                **kwargs,
            ).items()
        }
    )
    return headers


def _verify(key, headers, *, body=BODY, uri=URI, method="POST", **kwargs):
    return verify_request(
        public_key=_public(key),
        method=method,
        target_uri=uri,
        headers=headers,
        body=body,
        **kwargs,
    )


@pytest.mark.parametrize("kind", sorted(KEYS))
def test_a_signed_request_verifies(kind):
    key = KEYS[kind]
    result = _verify(key, _signed(key), expected_keyid="client-key-1")
    assert result.label == "sig1"
    assert result.tag == "fapi-2-request"


class TestWhatTheSignatureCovers:
    key = KEYS["rsa"]

    def test_a_changed_body_fails_the_digest(self):
        with pytest.raises(SignatureError, match="Content-Digest"):
            _verify(self.key, _signed(self.key), body=BODY + b"&person_id=x")

    def test_a_recomputed_digest_fails_the_signature(self):
        """Swapping the body and its digest together is caught because the
        digest header is itself signed."""
        tampered = BODY + b"&person_id=x"
        headers = _signed(self.key)
        headers["content-digest"] = content_digest(tampered)
        with pytest.raises(SignatureError, match="does not verify"):
            _verify(self.key, headers, body=tampered)

    def test_another_target_fails(self):
        with pytest.raises(SignatureError, match="does not verify"):
            _verify(self.key, _signed(self.key), uri="https://evil.example/token")

    def test_another_method_fails(self):
        with pytest.raises(SignatureError, match="does not verify"):
            _verify(self.key, _signed(self.key), method="PUT")

    def test_changed_client_credentials_fail(self):
        headers = _signed(self.key)
        headers["authorization"] = "Basic " + base64.b64encode(b"x:y").decode()
        with pytest.raises(SignatureError, match="does not verify"):
            _verify(self.key, headers)

    def test_another_key_fails(self):
        with pytest.raises(SignatureError, match="does not verify"):
            _verify(KEYS["ec"], _signed(self.key))


class TestParameters:
    key = KEYS["ec"]

    def test_a_signature_not_covering_the_required_components_is_refused(self):
        headers = _signed(self.key)
        label, _, raw = headers["signature-input"].partition("=")
        narrowed = raw.replace(' "content-digest"', "")
        headers["signature-input"] = f"{label}={narrowed}"
        with pytest.raises(SignatureError, match="does not cover"):
            _verify(self.key, headers)

    def test_a_lifetime_above_sixty_seconds_is_refused(self):
        with pytest.raises(SignatureError, match="60 seconds"):
            _verify(self.key, _signed(self.key, lifetime=120))

    def test_an_expired_signature_is_refused(self):
        headers = _signed(self.key, created=int(time.time()) - 600)
        with pytest.raises(SignatureError, match="expired"):
            _verify(self.key, headers)

    def test_a_signature_from_the_future_is_refused(self):
        headers = _signed(self.key, created=int(time.time()) + 600)
        with pytest.raises(SignatureError, match="future"):
            _verify(self.key, headers)

    def test_the_registered_key_id_must_match(self):
        with pytest.raises(SignatureError, match="key id"):
            _verify(self.key, _signed(self.key), expected_keyid="other-key")

    def test_headers_are_required(self):
        headers = _signed(self.key)
        del headers["signature"]
        with pytest.raises(SignatureError, match="required"):
            _verify(self.key, headers)


class TestContentDigest:
    def test_sha256_and_sha512_are_accepted(self):
        verify_content_digest(content_digest(BODY, "sha-256"), BODY)
        verify_content_digest(content_digest(BODY, "sha-512"), BODY)

    def test_an_unknown_algorithm_alone_proves_nothing(self):
        with pytest.raises(SignatureError, match="no supported"):
            verify_content_digest("md5=:AAAA:", BODY)

    def test_a_wrong_known_digest_fails_even_next_to_a_right_one(self):
        wrong = content_digest(b"other", "sha-256")
        with pytest.raises(SignatureError, match="does not match"):
            verify_content_digest(f"{content_digest(BODY)}, {wrong}", BODY)


def test_parses_the_guides_example_header():
    header = (
        'sig1=("@method" "@target-uri" "authorization" "content-digest");'
        "created=1764073861;expires=1764073921;"
        'keyid="snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio";tag="fapi-2-request"'
    )
    (parsed,) = parse_signature_input(header)
    assert parsed.components == (
        "@method",
        "@target-uri",
        "authorization",
        "content-digest",
    )
    assert parsed.expires - parsed.created == 60
    assert parsed.keyid == "snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio"


def test_weak_keys_are_not_registrable():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
    pem = (
        weak.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    with pytest.raises(ValueError, match="2048"):
        load_public_key(pem)
