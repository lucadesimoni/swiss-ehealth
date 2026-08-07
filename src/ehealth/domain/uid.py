"""Identifier primitives.

Three identifier families live here:

* ``Uid`` — the internal, type-prefixed, lexicographically sortable object
  identifier used for *every* entity in the system (persons, dossiers,
  medications, visitors, grants, ...).
* ``Ahvn13`` — the Swiss social security number (AHV/AVS, NAVS13). It is
  *validated* here but never persisted; see :mod:`ehealth.domain.identity`.
* ``CheUid`` — the Swiss business identification number (UID/IDE) that
  identifies healthcare institutions.

Nothing in this module touches the database or any secret material, which
keeps it trivially unit-testable.
"""

from __future__ import annotations

import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Final

# Crockford base32 — no I, L, O, U, so transcription mistakes are unlikely and
# the alphabet is case-insensitive on input.
_ALPHABET: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE: Final = {c: i for i, c in enumerate(_ALPHABET)}
# Accept the visually ambiguous characters on input, per the Crockford spec.
_DECODE.update({"I": 1, "L": 1, "O": 0, "i": 1, "l": 1, "o": 0})
_DECODE.update({c.lower(): i for i, c in enumerate(_ALPHABET)})

ULID_LEN: Final = 26


class IdentifierError(ValueError):
    """Raised when an identifier is structurally invalid."""


# --------------------------------------------------------------------------
# ULID
# --------------------------------------------------------------------------


def _encode(value: int, length: int) -> str:
    out = [""] * length
    for i in range(length - 1, -1, -1):
        out[i] = _ALPHABET[value & 0x1F]
        value >>= 5
    return "".join(out)


def new_ulid(now_ms: int | None = None) -> str:
    """Return a fresh ULID: 48 bit millisecond timestamp + 80 bit randomness.

    Sorting ULIDs lexicographically sorts them by creation time, which makes
    them usable as primary keys without leaking a sequential row count the way
    an auto-increment column does.
    """
    ts = int(time.time() * 1000) if now_ms is None else now_ms
    if not 0 <= ts < (1 << 48):
        raise IdentifierError("timestamp out of ULID range")
    return _encode(ts, 10) + _encode(int.from_bytes(os.urandom(10), "big"), 16)


def ulid_timestamp_ms(ulid: str) -> int:
    """Extract the creation timestamp (ms since epoch) from a ULID."""
    if len(ulid) != ULID_LEN:
        raise IdentifierError("ULID must be 26 characters")
    value = 0
    for char in ulid[:10]:
        try:
            value = value * 32 + _DECODE[char]
        except KeyError:
            raise IdentifierError(f"invalid ULID character {char!r}") from None
    return value


# --------------------------------------------------------------------------
# Type-prefixed object identifiers
# --------------------------------------------------------------------------

#: Registry of entity prefixes. Adding an entity type means adding it here, so
#: the set of things that can exist in the system is enumerable in one place.
UID_PREFIXES: Final[dict[str, str]] = {
    "pat": "patient",
    "hcp": "healthcare professional",
    "org": "healthcare institution",
    "vis": "visitor",
    "dos": "dossier",
    "doc": "dossier document",
    "med": "medicinal product",
    "mst": "medication statement",
    "cns": "consent",
    "grt": "access grant",
    "ses": "authentication session",
    "usr": "identity account",
    "req": "request correlation id",
}

_UID_RE: Final = re.compile(rf"^([a-z]{{3}})_([{_ALPHABET}]{{{ULID_LEN}}})$")


@dataclass(frozen=True, slots=True)
class Uid:
    """A type-prefixed object identifier, e.g. ``pat_01J8Z3K7QF9M2C4V6X8B0N5RTD``."""

    prefix: str
    ulid: str

    def __post_init__(self) -> None:
        if self.prefix not in UID_PREFIXES:
            raise IdentifierError(f"unknown UID prefix {self.prefix!r}")
        if len(self.ulid) != ULID_LEN:
            raise IdentifierError("UID body must be a 26 character ULID")

    @classmethod
    def generate(cls, prefix: str) -> "Uid":
        if prefix not in UID_PREFIXES:
            raise IdentifierError(f"unknown UID prefix {prefix!r}")
        return cls(prefix, new_ulid())

    @classmethod
    def parse(cls, raw: str) -> "Uid":
        match = _UID_RE.match(raw or "")
        if not match:
            raise IdentifierError(f"malformed UID {raw!r}")
        return cls(match.group(1), match.group(2))

    @classmethod
    def parse_typed(cls, raw: str, prefix: str) -> "Uid":
        """Parse and assert the entity type, so a visitor UID can never be
        passed where a patient UID is expected."""
        uid = cls.parse(raw)
        if uid.prefix != prefix:
            raise IdentifierError(
                f"expected a {UID_PREFIXES[prefix]} UID ({prefix}_...), got {uid.prefix}_..."
            )
        return uid

    @property
    def created_ms(self) -> int:
        return ulid_timestamp_ms(self.ulid)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.prefix}_{self.ulid}"


def new_uid(prefix: str) -> str:
    """Convenience wrapper returning the string form."""
    return str(Uid.generate(prefix))


# --------------------------------------------------------------------------
# AHVN13 — Swiss social security number
# --------------------------------------------------------------------------

_AHVN13_RE: Final = re.compile(r"^756\.?\d{4}\.?\d{4}\.?\d{2}$")


def _ean13_check_digit(digits: str) -> int:
    """EAN-13 check digit over the first twelve digits."""
    total = sum(int(d) * (3 if i % 2 else 1) for i, d in enumerate(digits[:12]))
    return (10 - total % 10) % 10


@dataclass(frozen=True, slots=True)
class Ahvn13:
    """A validated AHV number (756.xxxx.xxxx.xx).

    Instances deliberately do **not** implement ``__str__``/``__repr__`` in a
    way that reveals the number, so an accidental log statement cannot leak it.
    Call :meth:`reveal` to get the digits, which makes every such use greppable.
    """

    _digits: str

    def __post_init__(self) -> None:
        if len(self._digits) != 13 or not self._digits.isdigit():
            raise IdentifierError("AHVN13 must be 13 digits")

    @classmethod
    def parse(cls, raw: str) -> "Ahvn13":
        raw = (raw or "").strip()
        if not _AHVN13_RE.match(raw):
            raise IdentifierError("AHVN13 must look like 756.XXXX.XXXX.XX")
        digits = raw.replace(".", "")
        if int(digits[12]) != _ean13_check_digit(digits):
            raise IdentifierError("AHVN13 check digit is wrong")
        return cls(digits)

    @classmethod
    def is_valid(cls, raw: str) -> bool:
        try:
            cls.parse(raw)
        except IdentifierError:
            return False
        return True

    def reveal(self) -> str:
        """Return the raw 13 digits. Every call site is a data-protection
        relevant location and should be reviewed as such."""
        return self._digits

    def formatted(self) -> str:
        d = self._digits
        return f"{d[0:3]}.{d[3:7]}.{d[7:11]}.{d[11:13]}"

    def masked(self) -> str:
        """Safe for logs and support screens: ``756.****.****.42``."""
        return f"756.****.****.{self._digits[11:13]}"

    def __repr__(self) -> str:
        return f"Ahvn13({self.masked()})"

    __str__ = __repr__


def format_spid(digits: str) -> str:
    """Format a 13 digit sector identifier as ``761.xxxx.xxxx.xx``."""
    if len(digits) != 13 or not digits.isdigit():
        raise IdentifierError("SPID must be 13 digits")
    return f"{digits[0:3]}.{digits[3:7]}.{digits[7:11]}.{digits[11:13]}"


def spid_from_entropy(entropy: bytes, prefix: str = "761") -> str:
    """Build a syntactically valid 13 digit sector identifier from entropy.

    Layout mirrors the EPR-SPID: a three digit prefix, nine derived digits and
    an EAN-13 check digit. The derivation is done by the caller (see
    :mod:`ehealth.domain.identity`); this function only handles the encoding.
    """
    if len(prefix) != 3 or not prefix.isdigit():
        raise IdentifierError("SPID prefix must be three digits")
    if len(entropy) < 8:
        raise IdentifierError("need at least 64 bits of entropy")
    body = f"{int.from_bytes(entropy[:8], 'big') % 10**9:09d}"
    partial = prefix + body
    return partial + str(_ean13_check_digit(partial))


def is_valid_spid(raw: str) -> bool:
    digits = (raw or "").replace(".", "")
    if len(digits) != 13 or not digits.isdigit():
        return False
    return int(digits[12]) == _ean13_check_digit(digits)


# --------------------------------------------------------------------------
# CHE UID — Swiss business identification number (institutions)
# --------------------------------------------------------------------------

_CHE_RE: Final = re.compile(r"^CHE-?(\d{3})\.?(\d{3})\.?(\d{3})$", re.IGNORECASE)
_CHE_WEIGHTS: Final = (5, 4, 3, 2, 7, 6, 5, 4)


@dataclass(frozen=True, slots=True)
class CheUid:
    """Swiss enterprise identification number, e.g. ``CHE-116.281.277``."""

    digits: str

    @classmethod
    def parse(cls, raw: str) -> "CheUid":
        match = _CHE_RE.match((raw or "").strip())
        if not match:
            raise IdentifierError("CHE UID must look like CHE-123.456.789")
        digits = "".join(match.groups())
        remainder = sum(int(d) * w for d, w in zip(digits[:8], _CHE_WEIGHTS)) % 11
        check = 0 if remainder == 0 else 11 - remainder
        if check == 10:
            raise IdentifierError("CHE UID check digit cannot be 10")
        if check != int(digits[8]):
            raise IdentifierError("CHE UID check digit is wrong")
        return cls(digits)

    @classmethod
    def is_valid(cls, raw: str) -> bool:
        try:
            cls.parse(raw)
        except IdentifierError:
            return False
        return True

    def formatted(self) -> str:
        d = self.digits
        return f"CHE-{d[0:3]}.{d[3:6]}.{d[6:9]}"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.formatted()


# --------------------------------------------------------------------------
# GTIN — used to identify medicinal product packages
# --------------------------------------------------------------------------


def is_valid_gtin(raw: str) -> bool:
    """Validate a GTIN-8/12/13/14 (Swissmedic packages carry GTIN-13/14)."""
    digits = (raw or "").strip()
    if not digits.isdigit() or len(digits) not in (8, 12, 13, 14):
        return False
    body, check = digits[:-1], int(digits[-1])
    # Weights alternate 3/1 from the right-hand side.
    total = sum(int(d) * (3 if (len(body) - i) % 2 else 1) for i, d in enumerate(body))
    return (10 - total % 10) % 10 == check


def random_token(nbytes: int = 32) -> str:
    """URL-safe random string for one-time codes and correlation ids."""
    return secrets.token_urlsafe(nbytes)
