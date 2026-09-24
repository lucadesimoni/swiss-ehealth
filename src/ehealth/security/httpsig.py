# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""HTTP message signatures (RFC 9421) and content digests (RFC 9530).

CH EPR FHIR v5.0.0 requires every request to the IUA token endpoint to be
signed with the client's registered private key. The signature has to cover
``@method``, ``@target-uri``, ``authorization`` and ``content-digest``, carry
``created`` and ``expires`` (at most 60 seconds apart), and be checked against
the public key registered for that ``client_id`` at onboarding.

That is the whole of RFC 9421 this module implements. Anything else in a
``Signature-Input`` header — a component we do not know, a missing required
one, a lifetime above 60 seconds — is refused rather than skipped, because
a signature that silently covers less than expected is worse than none.

Algorithms are fixed by the registered key, never by the request:
RSA keys verify as ``rsa-v1_5-sha256`` (which the guide requires servers to
support), EC P-256 as ``ecdsa-p256-sha256``, Ed25519 as ``ed25519``. There is
no HMAC: the guide forbids shared-key algorithms at the token endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

#: The components the guide requires the signature to cover, in its order.
REQUIRED_COMPONENTS = ("@method", "@target-uri", "authorization", "content-digest")

#: ``expires - created`` may not exceed this (CH EPR FHIR, ITI-71).
MAX_SIGNATURE_LIFETIME = 60

_DIGESTS = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}

_MEMBER = re.compile(
    r'\s*([a-z*][a-z0-9_\-.*]*)=(\((?:\s*"[^"]*")*\s*\)'
    r'(?:;[a-z*][a-z0-9_\-.*]*=(?:"(?:[^"\\]|\\.)*"|-?\d+))*)\s*(?:,|$)'
)
_PARAM = re.compile(r';([a-z*][a-z0-9_\-.*]*)=("(?:[^"\\]|\\.)*"|-?\d+)')
_SIGNATURE = re.compile(r"\s*([a-z*][a-z0-9_\-.*]*)=:([A-Za-z0-9+/=]*):\s*(?:,|$)")


class SignatureError(Exception):
    """The request is not signed as required. Safe to log, not to return."""


@dataclass(frozen=True, slots=True)
class SignatureInput:
    label: str
    components: tuple[str, ...]
    #: The serialised inner list with its parameters, exactly as received:
    #: it is signed verbatim as ``@signature-params``.
    raw: str
    created: int
    expires: int
    keyid: str | None
    tag: str | None


# --------------------------------------------------------------------------
# Content-Digest (RFC 9530)
# --------------------------------------------------------------------------


def content_digest(body: bytes, algorithm: str = "sha-512") -> str:
    digest = _DIGESTS[algorithm](body).digest()
    return f"{algorithm}=:{base64.b64encode(digest).decode('ascii')}:"


def verify_content_digest(header: str | None, body: bytes) -> None:
    """At least one listed digest must be a known algorithm, and every known
    one must match. An unknown algorithm alone proves nothing."""
    if not header:
        raise SignatureError("Content-Digest is required")
    checked = False
    for member in header.split(","):
        name, _, value = member.strip().partition("=")
        function = _DIGESTS.get(name.strip().lower())
        if function is None:
            continue
        value = value.strip()
        if not (value.startswith(":") and value.endswith(":")):
            raise SignatureError("Content-Digest value is malformed")
        try:
            claimed = base64.b64decode(value[1:-1], validate=True)
        except ValueError as exc:
            raise SignatureError("Content-Digest value is not base64") from exc
        if claimed != function(body).digest():
            raise SignatureError("Content-Digest does not match the body")
        checked = True
    if not checked:
        raise SignatureError("Content-Digest uses no supported algorithm")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def _unquote(value: str) -> str:
    return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def parse_signature_input(header: str) -> list[SignatureInput]:
    if len(header) > 4096:
        raise SignatureError("Signature-Input is implausibly large")
    out: list[SignatureInput] = []
    position = 0
    while position < len(header):
        match = _MEMBER.match(header, position)
        if match is None:
            raise SignatureError("Signature-Input is malformed")
        label, raw = match.group(1), match.group(2)
        inner, _, _ = raw.partition(")")
        components = tuple(re.findall(r'"([^"]*)"', inner + ")"))
        params: dict[str, str] = {}
        for name, value in _PARAM.findall(raw[len(inner) + 1 :]):
            if name in params:
                raise SignatureError(f"duplicate signature parameter {name!r}")
            params[name] = value
        try:
            created = int(params["created"])
            expires = int(params["expires"])
        except (KeyError, ValueError) as exc:
            raise SignatureError("created and expires are required") from exc
        out.append(
            SignatureInput(
                label=label,
                components=components,
                raw=raw,
                created=created,
                expires=expires,
                keyid=_unquote(params["keyid"]) if "keyid" in params else None,
                tag=_unquote(params["tag"]) if "tag" in params else None,
            )
        )
        position = match.end()
    return out


def parse_signatures(header: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    position = 0
    while position < len(header):
        match = _SIGNATURE.match(header, position)
        if match is None:
            raise SignatureError("Signature is malformed")
        try:
            out[match.group(1)] = base64.b64decode(match.group(2), validate=True)
        except ValueError as exc:
            raise SignatureError("Signature is not base64") from exc
        position = match.end()
    return out


# --------------------------------------------------------------------------
# Signature base
# --------------------------------------------------------------------------


def signature_base(
    signature_input: SignatureInput,
    *,
    method: str,
    target_uri: str,
    headers: dict[str, str],
) -> bytes:
    lines = []
    for component in signature_input.components:
        if component == "@method":
            value = method.upper()
        elif component == "@target-uri":
            value = target_uri
        elif component.startswith("@"):
            raise SignatureError(f"unsupported derived component {component!r}")
        else:
            value = headers.get(component)
            if value is None:
                raise SignatureError(f"covered header {component!r} is missing")
            # RFC 9421 §2.1: strip, and join repeated fields with ", ".
            value = value.strip()
        if "\n" in value or "\r" in value:
            raise SignatureError("component values must not contain newlines")
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {signature_input.raw}')
    return "\n".join(lines).encode("utf-8")


# --------------------------------------------------------------------------
# Keys and algorithms
# --------------------------------------------------------------------------


def load_public_key(pem: str) -> Any:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise ValueError("RSA keys must be at least 2048 bits")
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("EC keys must be on P-256")
    elif not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("only RSA, EC P-256 and Ed25519 keys are accepted")
    return key


def _verify(key: Any, signature: bytes, message: bytes) -> bool:
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if len(signature) != 64:
                return False
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        else:  # pragma: no cover - load_public_key refuses anything else
            return False
    except InvalidSignature:
        return False
    return True


def _sign(key: Any, message: bytes) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(message)
    raise ValueError("unsupported private key type")


# --------------------------------------------------------------------------
# Verification and signing
# --------------------------------------------------------------------------


def verify_request(
    *,
    public_key: Any,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes,
    expected_keyid: str | None = None,
    now: int | None = None,
    skew: int = 30,
) -> SignatureInput:
    """Verify a signed token request. Returns the signature that verified.

    ``headers`` must have lower-case names. Only signatures covering every
    required component are considered; one of them has to verify.
    """
    now = int(time.time()) if now is None else now
    verify_content_digest(headers.get("content-digest"), body)
    raw_input = headers.get("signature-input")
    raw_signature = headers.get("signature")
    if not raw_input or not raw_signature:
        raise SignatureError("Signature-Input and Signature are required")
    signatures = parse_signatures(raw_signature)
    reasons = []
    for candidate in parse_signature_input(raw_input):
        missing = [c for c in REQUIRED_COMPONENTS if c not in candidate.components]
        if missing:
            reasons.append(f"{candidate.label}: does not cover {missing}")
            continue
        if candidate.expires - candidate.created > MAX_SIGNATURE_LIFETIME:
            reasons.append(f"{candidate.label}: lifetime above 60 seconds")
            continue
        if candidate.expires <= candidate.created:
            reasons.append(f"{candidate.label}: expires before it is created")
            continue
        if candidate.created - skew > now:
            reasons.append(f"{candidate.label}: created in the future")
            continue
        if now - skew >= candidate.expires:
            reasons.append(f"{candidate.label}: expired")
            continue
        if expected_keyid and candidate.keyid and candidate.keyid != expected_keyid:
            reasons.append(f"{candidate.label}: key id is not the registered one")
            continue
        signature = signatures.get(candidate.label)
        if signature is None:
            reasons.append(f"{candidate.label}: no matching Signature member")
            continue
        base = signature_base(
            candidate, method=method, target_uri=target_uri, headers=headers
        )
        if _verify(public_key, signature, base):
            return candidate
        reasons.append(f"{candidate.label}: signature does not verify")
    raise SignatureError("; ".join(reasons) or "no usable signature")


def sign_request(
    *,
    private_key: Any,
    method: str,
    target_uri: str,
    headers: dict[str, str],
    body: bytes,
    keyid: str | None = None,
    tag: str | None = "fapi-2-request",
    created: int | None = None,
    lifetime: int = 60,
    label: str = "sig1",
) -> dict[str, str]:
    """The headers a client adds to sign a token request.

    Used by the tests and by any IUA Authorization Client built on this
    codebase; the server side never signs requests.
    """
    created = int(time.time()) if created is None else created
    lowered = {k.lower(): v for k, v in headers.items()}
    lowered["content-digest"] = content_digest(body)
    covered = " ".join(f'"{c}"' for c in REQUIRED_COMPONENTS)
    raw = f"({covered});created={created};expires={created + lifetime}"
    if keyid:
        raw += f';keyid="{keyid}"'
    if tag:
        raw += f';tag="{tag}"'
    signature_input = SignatureInput(
        label=label,
        components=REQUIRED_COMPONENTS,
        raw=raw,
        created=created,
        expires=created + lifetime,
        keyid=keyid,
        tag=tag,
    )
    base = signature_base(
        signature_input, method=method, target_uri=target_uri, headers=lowered
    )
    signature = base64.b64encode(_sign(private_key, base)).decode("ascii")
    return {
        "Content-Digest": lowered["content-digest"],
        "Signature-Input": f"{label}={raw}",
        "Signature": f"{label}=:{signature}:",
    }
