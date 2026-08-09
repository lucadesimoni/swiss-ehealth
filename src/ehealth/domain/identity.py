# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Deriving person identity from the AHV number without storing it.

Why the AHV number is not simply used as the key
------------------------------------------------

Swiss law (EPDG/LEPD art. 5 and the implementing EPDV) deliberately does *not*
use the AHVN13 as the identifier inside the electronic patient record. The
central compensation office derives a separate sector identifier (EPR-SPID)
from it, so a leak of health data cannot be trivially joined against the
tax, pension or employer systems that also key on the AHVN13. AHVG art. 50g
likewise constrains who may use the AHVN13 systematically at all.

This module implements that separation locally:

``ahvn13``  --HMAC(sector key)-->  ``ppid``  (256 bit, internal linkage key)
                               \\-->  ``spid`` (18 digit EPR-SPID, interop facing)
                               \\-->  ``lookup_index`` (rotatable blind index)

The AHVN13 itself is either discarded immediately after derivation, or —
when the deployment needs to re-derive after a key rotation or to answer a
lawful disclosure request — kept only as an AEAD-sealed blob bound to the
``ppid``. Which of the two applies is a deployment decision, not a code
change: see ``settings.store_sealed_ahvn``.

Two notes on the EPR-SPID:

* It is **18 digits** (prefix 761), not 13 like the AHVN13 it derives from.
  Confusing the two lengths is the most common error in Swiss e-health
  integrations, so both are validated strictly and separately.
* In a certified deployment it is **allocated by the ZAS UPI service**, not
  computed locally. Deriving it here produces a correctly shaped, stable
  identifier for deployments not connected to the UPI; the allocation loop
  and the uniqueness constraint stay either way, so swapping in a real UPI
  client changes one method and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from ehealth.domain.uid import SPID_PREFIX, Ahvn13, spid_from_entropy
from ehealth.security.crypto import KeyPurpose, KeyRing, b64u

#: How many candidate SPIDs to try before giving up on allocation. With
#: fourteen significant digits a collision is vanishingly unlikely, but the
#: probe stays because two patients sharing an identifier is not a failure
#: mode worth risking.
MAX_SPID_ATTEMPTS = 64


@dataclass(frozen=True, slots=True)
class DerivedIdentity:
    """Everything derivable from an AHVN13, and nothing that reveals it."""

    #: Stable 256 bit pseudonym. The join key for all health data.
    ppid: str
    #: Rotatable keyed index, used to answer "do we already know this person".
    lookup_index: str
    #: AEAD envelope over the AHVN13, or ``None`` in zero-retention mode.
    sealed_ahvn: str | None


class IdentityService:
    """Derives pseudonymous identity from an AHV number.

    The service is stateless; all secret material lives in the
    :class:`~ehealth.security.crypto.KeyRing`.
    """

    def __init__(self, keyring: KeyRing, *, store_sealed_ahvn: bool = True) -> None:
        self._keys = keyring
        self._store_sealed = store_sealed_ahvn

    # -- derivation -------------------------------------------------------

    def ppid(self, ahvn: Ahvn13) -> str:
        """Stable pseudonymous person id.

        Deterministic across institutions sharing a root key, which is what
        makes patient matching possible without a central plaintext register.
        The pseudonym key version is *not* rotated in place: rotating it would
        re-identify nobody but would break every existing linkage. Migration
        to a new version is an explicit, re-enrolment style operation.
        """
        digest = self._keys.mac(
            KeyPurpose.PERSON_PSEUDONYM, b"ahvn13|" + ahvn.reveal().encode("ascii")
        )
        version = self._keys.current_version(KeyPurpose.PERSON_PSEUDONYM)
        return f"p{version}_{b64u(digest)}"

    def lookup_index(self, ahvn: Ahvn13) -> str:
        """Blind index for equality search on the AHVN13.

        Separate key from the pseudonym so that compromising the search index
        does not compromise the linkage key, and rotatable because it can be
        rebuilt from the sealed copy.
        """
        return self._keys.blind_index(
            KeyPurpose.PERSON_LOOKUP_INDEX, b"ahvn13|" + ahvn.reveal().encode("ascii")
        )

    def spid_candidates(self, ahvn: Ahvn13) -> Iterator[str]:
        """Yield deterministic 18 digit EPR-SPID candidates for allocation.

        The first candidate is a pure function of the AHVN13; subsequent ones
        exist only to resolve the rare collision, and the allocated value is
        recorded so the mapping stays stable afterwards.

        **This is a stand-in.** In a certified EPDG deployment the EPR-SPID is
        allocated by the ZAS UPI service and queried, not computed — see the
        note in the module docstring. Deriving it locally gives a correctly
        shaped identifier with the same stability properties for a deployment
        that is not (yet) connected to the UPI.
        """
        for attempt in range(MAX_SPID_ATTEMPTS):
            entropy = self._keys.mac(
                KeyPurpose.SECTOR_ID,
                b"spid|%d|%s" % (attempt, ahvn.reveal().encode("ascii")),
            )
            yield spid_from_entropy(entropy, SPID_PREFIX)

    def derive(self, ahvn: Ahvn13) -> DerivedIdentity:
        ppid = self.ppid(ahvn)
        sealed = None
        if self._store_sealed:
            sealed = self._keys.encrypt(
                KeyPurpose.FIELD_ENCRYPTION,
                ahvn.reveal().encode("ascii"),
                aad=self._ahvn_aad(ppid),
            )
        return DerivedIdentity(
            ppid=ppid, lookup_index=self.lookup_index(ahvn), sealed_ahvn=sealed
        )

    # -- controlled re-identification -------------------------------------

    def unseal(self, sealed_ahvn: str, ppid: str) -> Ahvn13:
        """Recover the AHVN13. Callers **must** write an audit event first.

        Only two legitimate callers exist: key rotation (rebuilding blind
        indices) and a lawful disclosure request. Both are privileged
        operations in :mod:`ehealth.api.routes_admin`.
        """
        plaintext = self._keys.decrypt(sealed_ahvn, aad=self._ahvn_aad(ppid))
        return Ahvn13.parse(plaintext.decode("ascii"))

    @staticmethod
    def _ahvn_aad(ppid: str) -> bytes:
        # Binding to the ppid means a sealed AHVN13 cannot be transplanted
        # onto a different person's row.
        return b"ahvn13-seal|" + ppid.encode("ascii")

    # -- field level protection for direct identifiers --------------------

    def seal_field(self, entity_uid: str, field: str, value: str) -> str:
        return self._keys.encrypt(
            KeyPurpose.FIELD_ENCRYPTION,
            value.encode("utf-8"),
            aad=self._field_aad(entity_uid, field),
        )

    def open_field(self, entity_uid: str, field: str, envelope: str) -> str:
        return self._keys.decrypt(
            envelope, aad=self._field_aad(entity_uid, field)
        ).decode("utf-8")

    @staticmethod
    def _field_aad(entity_uid: str, field: str) -> bytes:
        return f"field|{entity_uid}|{field}".encode()
