# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
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
    #: Every natural person, whatever roles they hold. A physician who is also
    #: a patient is one person with one UID; which roles they may act in is a
    #: database question (``person_role``), not a syntactic one.
    "per": "person",
    "org": "healthcare institution",
    "dos": "dossier",
    "doc": "dossier document",
    "med": "medicinal product",
    "mst": "medication statement",
    "cns": "consent",
    "crd": "professional credential",
    "grt": "access grant",
    "ses": "authentication session",
    "usr": "identity account",
    "req": "request correlation id",
    "iua": "IUA access token or authorisation code",
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
    def generate(cls, prefix: str) -> Uid:
        if prefix not in UID_PREFIXES:
            raise IdentifierError(f"unknown UID prefix {prefix!r}")
        return cls(prefix, new_ulid())

    @classmethod
    def parse(cls, raw: str) -> Uid:
        match = _UID_RE.match(raw or "")
        if not match:
            raise IdentifierError(f"malformed UID {raw!r}")
        return cls(match.group(1), match.group(2))

    @classmethod
    def parse_typed(cls, raw: str, prefix: str) -> Uid:
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
    def parse(cls, raw: str) -> Ahvn13:
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


# --------------------------------------------------------------------------
# EPR-SPID — the patient identifier of the electronic patient record
# --------------------------------------------------------------------------

#: The EPR-SPID is **18 digits**, prefix 761 — not 13 like the AHVN13 it is
#: derived from. Mixing the two lengths up is the single most common error in
#: Swiss e-health integrations, so both are validated strictly and separately.
SPID_LENGTH: Final = 18
SPID_PREFIX: Final = "761"

#: Digits the derivation may fill: prefix (3) + body (14) + check digit (1).
SPID_BODY_LENGTH: Final = SPID_LENGTH - len(SPID_PREFIX) - 1


def _mod10_check_digit(digits: str) -> int:
    """GS1 mod-10 check digit, weights alternating 3/1 from the right.

    The same scheme EAN-13 uses, stated for an arbitrary length so it works
    for the 18 digit SPID as well as for 13 digit GTINs.
    """
    total = sum(
        int(d) * (3 if (len(digits) - i) % 2 else 1) for i, d in enumerate(digits)
    )
    return (10 - total % 10) % 10


def format_spid(digits: str) -> str:
    """Normalise an EPR-SPID to its canonical 18 digit form.

    The EPR-SPID is written without separators — unlike the AHVN13, which is
    conventionally dotted. Keeping the two visually distinct is deliberate:
    a human reading a record should never have to count digits to know which
    identifier they are looking at.
    """
    digits = (digits or "").replace(".", "").replace(" ", "")
    if len(digits) != SPID_LENGTH or not digits.isdigit():
        raise IdentifierError(f"EPR-SPID must be {SPID_LENGTH} digits")
    if not digits.startswith(SPID_PREFIX):
        raise IdentifierError(f"EPR-SPID must start with {SPID_PREFIX}")
    return digits


def spid_from_entropy(entropy: bytes, prefix: str = SPID_PREFIX) -> str:
    """Build a syntactically valid 18 digit EPR-SPID from entropy.

    Layout: three digit prefix, fourteen derived digits, one mod-10 check
    digit. Fourteen significant digits make collisions a non-issue at any
    realistic population size, which is what the 13 digit version got wrong.

    This produces an identifier of the right *shape*. In a real EPDG
    deployment the SPID is **allocated by the ZAS UPI service**, not derived
    locally — see :class:`~ehealth.domain.identity.SpidProvider` for the seam
    where that client belongs.
    """
    if len(prefix) != 3 or not prefix.isdigit():
        raise IdentifierError("EPR-SPID prefix must be three digits")
    if len(entropy) < 16:
        raise IdentifierError("need at least 128 bits of entropy")
    body = f"{int.from_bytes(entropy[:16], 'big') % 10**SPID_BODY_LENGTH:0{SPID_BODY_LENGTH}d}"
    partial = prefix + body
    return partial + str(_mod10_check_digit(partial))


def is_valid_spid(raw: str) -> bool:
    digits = (raw or "").replace(".", "").replace(" ", "")
    if len(digits) != SPID_LENGTH or not digits.isdigit():
        return False
    if not digits.startswith(SPID_PREFIX):
        return False
    return int(digits[-1]) == _mod10_check_digit(digits[:-1])


# --------------------------------------------------------------------------
# VeKa — the health insurance card number (KVG)
# --------------------------------------------------------------------------

#: 20 digits beginning 80756: "80" for health insurance, "756" for
#: Switzerland, per the Versichertenkarte specification under KVG/KVV.
VEKA_LENGTH: Final = 20
VEKA_PREFIX: Final = "80756"


def is_valid_veka(raw: str) -> bool:
    """Structural validation of a health insurance card number.

    Length and prefix only. The check digit scheme of the VeKa number is not
    reproduced here because getting it wrong would silently reject valid
    cards; a deployment that needs full validation should implement it against
    the current Versichertenkarte specification and replace this function.
    """
    digits = (raw or "").replace(".", "").replace(" ", "")
    return (
        len(digits) == VEKA_LENGTH
        and digits.isdigit()
        and digits.startswith(VEKA_PREFIX)
    )


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
    def parse(cls, raw: str) -> CheUid:
        match = _CHE_RE.match((raw or "").strip())
        if not match:
            raise IdentifierError("CHE UID must look like CHE-123.456.789")
        digits = "".join(match.groups())
        # strict=True: the regex guarantees eight digits today, and if that
        # ever changes silently, a short zip would compute a plausible but
        # wrong check digit rather than raise.
        remainder = (
            sum(int(d) * w for d, w in zip(digits[:8], _CHE_WEIGHTS, strict=True)) % 11
        )
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
    return int(digits[-1]) == _mod10_check_digit(digits[:-1])


# --------------------------------------------------------------------------
# Healthcare professionals — the identifiers Swiss law and practice use
# --------------------------------------------------------------------------


def is_valid_gln(raw: str) -> bool:
    """A GLN is a GTIN-13 and carries the same check digit.

    Every professional listed in MedReg (MedBG art. 51 ff.), NAREG (GesBG) or
    PsyReg (PsyG) carries one, administered by Refdata. It is the identifier
    the EPD, e-prescriptions and e-invoicing all key on, which makes it the
    right primary handle for a professional here.
    """
    digits = (raw or "").strip()
    return len(digits) == 13 and digits.isdigit() and is_valid_gtin(digits)


#: ZSR / RCC — the billing number issued by SASIS, one uppercase letter
#: followed by six digits (e.g. ``A123456``). Required to invoice a Swiss
#: insurer under KVG; it says nothing about clinical authority, which is why
#: it is recorded separately from the practice licence.
_ZSR_RE: Final = re.compile(r"^([A-Z])\.?(\d{6})$")


def normalise_zsr(raw: str) -> str:
    match = _ZSR_RE.match((raw or "").strip().upper().replace(" ", ""))
    if not match:
        raise IdentifierError("ZSR/RCC number must look like A123456")
    return f"{match.group(1)}{match.group(2)}"


def is_valid_zsr(raw: str) -> bool:
    try:
        normalise_zsr(raw)
    except IdentifierError:
        return False
    return True


# --------------------------------------------------------------------------
# Medicinal products — Swissmedic and Refdata identifiers
# --------------------------------------------------------------------------

#: Swissmedic authorisation number (Zulassungsnummer) under HMG art. 9 ff.
#: Five digits, optionally with a package suffix, e.g. ``62536`` or
#: ``62536 001``. Digits only after normalisation.
_SWISSMEDIC_RE: Final = re.compile(r"^(\d{5})[\s.-]?(\d{1,3})?$")


def normalise_swissmedic_authorisation(raw: str) -> str:
    """Return ``NNNNN`` or ``NNNNN-SSS`` for an authorisation number."""
    match = _SWISSMEDIC_RE.match((raw or "").strip())
    if not match:
        raise IdentifierError(
            "Swissmedic authorisation number must be five digits, "
            "optionally with a package suffix"
        )
    base, suffix = match.groups()
    return f"{base}-{int(suffix):03d}" if suffix else base


def is_valid_swissmedic_authorisation(raw: str) -> bool:
    try:
        normalise_swissmedic_authorisation(raw)
    except IdentifierError:
        return False
    return True


def is_valid_pharmacode(raw: str) -> bool:
    """Refdata Pharmacode: the Swiss article number, up to seven digits.

    No check digit exists, so this is a format check only — stated plainly
    rather than implied, because a validator that looks stricter than it is
    invites misplaced trust.
    """
    digits = (raw or "").strip().lstrip("0")
    return bool(digits) and digits.isdigit() and len(digits) <= 7


#: ATC (WHO): one letter, two digits, two letters, two digits — e.g. C09AA03.
#: Prefixes are valid too; a product may be classified at any depth.
_ATC_RE: Final = re.compile(r"^[A-Z](\d{2}([A-Z]([A-Z](\d{2})?)?)?)?$")


def is_valid_atc(raw: str) -> bool:
    return bool(_ATC_RE.match((raw or "").strip().upper()))


def random_token(nbytes: int = 32) -> str:
    """URL-safe random string for one-time codes and correlation ids."""
    return secrets.token_urlsafe(nbytes)
