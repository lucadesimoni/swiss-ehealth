"""Cryptographic core: key hierarchy, keyed hashing, AEAD, signatures.

Design rules enforced here:

* **One root secret, everything else derived.** Operators supply a single
  high-entropy root key (from an HSM/KMS in production). All subkeys are
  HKDF-derived from it with a purpose label and a version number, so key
  separation is structural rather than a matter of discipline.
* **Everything is versioned.** Ciphertexts, MACs and signatures all carry the
  algorithm and key version they were produced with, so a key can be rotated
  or an algorithm replaced without a flag day. That is what makes the system
  crypto-agile, which is the only realistic form of "post-quantum ready"
  today: see :data:`SIGNATURE_ALGORITHMS`.
* **AEAD is always bound to context.** Encrypted fields authenticate the
  entity UID and column name as associated data, so a ciphertext cannot be
  moved from one patient's row to another's.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT_KEY_BYTES: Final = 32
_NONCE_BYTES: Final = 12


class CryptoError(Exception):
    """Raised on any verification or decryption failure."""


class KeyPurpose(StrEnum):
    """HKDF labels. Never reuse a label for two different operations."""

    #: Derives the stable pseudonymous person id from the AHVN13.
    PERSON_PSEUDONYM = "person-pseudonym"
    #: Derives the searchable blind index over the AHVN13.
    PERSON_LOOKUP_INDEX = "person-lookup-index"
    #: Allocates the 13 digit sector identifier (EPR-SPID analogue).
    SECTOR_ID = "sector-id"
    #: Field-level envelope encryption of directly identifying data.
    FIELD_ENCRYPTION = "field-encryption"
    #: Signs the append-only audit ledger.
    AUDIT_LEDGER = "audit-ledger"
    #: Signs capability and session tokens.
    TOKEN_SIGNING = "token-signing"
    #: Hashes one-time second-factor codes and refresh tokens.
    OTP_BINDING = "otp-binding"


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(raw + padding)
    except Exception as exc:  # noqa: BLE001 - normalise to our error type
        raise CryptoError("invalid base64url input") from exc


def canonical_json(payload: Any) -> bytes:
    """Deterministic JSON encoding — the byte string that gets signed.

    Sorted keys, no insignificant whitespace, no non-ASCII escapes surprises.
    Two structurally equal payloads must always produce identical bytes,
    otherwise signatures would be unverifiable across implementations.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def constant_time_equals(left: str | bytes, right: str | bytes) -> bool:
    if isinstance(left, str):
        left = left.encode("utf-8")
    if isinstance(right, str):
        right = right.encode("utf-8")
    return hmac.compare_digest(left, right)


# --------------------------------------------------------------------------
# Algorithm registry
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignatureAlgorithm:
    name: str
    #: ``False`` marks an algorithm we can still verify but no longer issue.
    issuing: bool
    #: Set once a post-quantum implementation is wired in.
    available: bool = True


#: The single place to look when asking "what signs what, and can we move off
#: it".  Adding ML-DSA-65 (FIPS 204) alongside Ed25519 is a matter of
#: registering it here and implementing :class:`Signer` for it; every consumer
#: already reads the algorithm from the envelope rather than assuming one.
SIGNATURE_ALGORITHMS: Final[dict[str, SignatureAlgorithm]] = {
    "Ed25519": SignatureAlgorithm("Ed25519", issuing=True),
    "ML-DSA-65": SignatureAlgorithm("ML-DSA-65", issuing=False, available=False),
    "Ed25519+ML-DSA-65": SignatureAlgorithm(
        "Ed25519+ML-DSA-65", issuing=False, available=False
    ),
}

DEFAULT_SIGNATURE_ALGORITHM: Final = "Ed25519"


# --------------------------------------------------------------------------
# Key hierarchy
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DerivedKey:
    purpose: KeyPurpose
    version: int
    material: bytes

    @property
    def kid(self) -> str:
        """Key id embedded in envelopes: ``field-encryption.v2``."""
        return f"{self.purpose.value}.v{self.version}"


class KeyRing:
    """Derives and caches all subkeys from the operator-supplied root secret.

    ``current_versions`` maps a purpose to the version used for *new*
    material. Older versions stay derivable, so rotation is: bump the current
    version, keep verifying/decrypting old envelopes, re-wrap lazily.
    """

    def __init__(
        self,
        root_key: bytes,
        current_versions: dict[KeyPurpose, int] | None = None,
    ) -> None:
        if len(root_key) < ROOT_KEY_BYTES:
            raise CryptoError(
                f"root key must be at least {ROOT_KEY_BYTES} bytes of entropy"
            )
        self._root = root_key
        self._current = {p: 1 for p in KeyPurpose} | (current_versions or {})
        self._cache: dict[tuple[KeyPurpose, int], DerivedKey] = {}

    @classmethod
    def from_base64(
        cls, encoded: str, current_versions: dict[KeyPurpose, int] | None = None
    ) -> "KeyRing":
        return cls(b64u_decode(encoded), current_versions)

    @classmethod
    def generate(cls) -> "KeyRing":
        """Ephemeral keyring — development and tests only."""
        return cls(os.urandom(ROOT_KEY_BYTES))

    def current_version(self, purpose: KeyPurpose) -> int:
        return self._current[purpose]

    def key(self, purpose: KeyPurpose, version: int | None = None) -> DerivedKey:
        version = self._current[purpose] if version is None else version
        if version < 1:
            raise CryptoError("key version must be >= 1")
        cached = self._cache.get((purpose, version))
        if cached is not None:
            return cached
        material = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=f"ch.ehealth.{purpose.value}.v{version}".encode("utf-8"),
        ).derive(self._root)
        derived = DerivedKey(purpose, version, material)
        self._cache[(purpose, version)] = derived
        return derived

    # -- keyed hashing ----------------------------------------------------

    def mac(
        self, purpose: KeyPurpose, data: bytes, version: int | None = None
    ) -> bytes:
        return hmac.new(self.key(purpose, version).material, data, hashlib.sha256).digest()

    def blind_index(
        self, purpose: KeyPurpose, data: bytes, version: int | None = None
    ) -> str:
        """Keyed, versioned lookup index.

        Prefixed with the key version so the index can be rebuilt under a new
        key while old rows remain searchable during the migration.
        """
        version = self._current[purpose] if version is None else version
        return f"v{version}:{b64u(self.mac(purpose, data, version))}"

    # -- envelope encryption ----------------------------------------------

    def encrypt(
        self, purpose: KeyPurpose, plaintext: bytes, *, aad: bytes
    ) -> str:
        key = self.key(purpose)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(key.material).encrypt(nonce, plaintext, aad)
        return f"v1.{key.kid}.{b64u(nonce)}.{b64u(ciphertext)}"

    def decrypt(self, envelope: str, *, aad: bytes) -> bytes:
        # The key id itself contains a dot ("field-encryption.v1"), so the
        # envelope is parsed from both ends rather than by a field count.
        parts = envelope.split(".")
        if len(parts) < 5:
            raise CryptoError("malformed ciphertext envelope")
        scheme, nonce_b64, ct_b64 = parts[0], parts[-2], parts[-1]
        kid = ".".join(parts[1:-2])
        try:
            purpose_name, version_name = kid.rsplit(".v", 1)
        except ValueError:
            raise CryptoError("malformed ciphertext envelope") from None
        if scheme != "v1":
            raise CryptoError(f"unsupported envelope scheme {scheme!r}")
        try:
            purpose = KeyPurpose(purpose_name)
            version = int(version_name)
        except ValueError:
            raise CryptoError("unknown key id in envelope") from None
        key = self.key(purpose, version)
        try:
            return AESGCM(key.material).decrypt(
                b64u_decode(nonce_b64), b64u_decode(ct_b64), aad
            )
        except Exception as exc:  # noqa: BLE001
            raise CryptoError("ciphertext failed authentication") from exc

    # -- signing ----------------------------------------------------------

    def signer(self, purpose: KeyPurpose, version: int | None = None) -> "Signer":
        """Deterministically derive the Ed25519 keypair for a purpose.

        Deriving rather than storing means a restored backup of the root key
        restores every signing identity, and there is no second secret store
        to keep in sync.
        """
        return Signer(self.key(purpose, version))


class Signer:
    """Ed25519 signer over canonical JSON, with an algorithm-tagged envelope."""

    algorithm: Final = DEFAULT_SIGNATURE_ALGORITHM

    def __init__(self, key: DerivedKey) -> None:
        self._key = key
        self._private = Ed25519PrivateKey.from_private_bytes(key.material)
        self._public: Ed25519PublicKey = self._private.public_key()

    @property
    def kid(self) -> str:
        return self._key.kid

    @property
    def public_key_b64(self) -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return b64u(
            self._public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        )

    def sign(self, message: bytes) -> str:
        return b64u(self._private.sign(message))

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            self._private.public_key().verify(b64u_decode(signature), message)
        except (InvalidSignature, CryptoError):
            return False
        return True


def hash_chain_link(previous_hash: bytes, payload: bytes) -> bytes:
    """One link of the tamper-evident ledger.

    Domain-separated so a payload can never be reinterpreted as a chain head.
    """
    return sha256(b"ch.ehealth.ledger.v1\x00" + previous_hash + b"\x00" + payload)


GENESIS_HASH: Final = b"\x00" * 32
