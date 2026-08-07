# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Offline bundles: the patient's record, in their own hands.

Two problems, one mechanism.

**The ambulance problem.** Someone collapses in a village at 02:00 with no
coverage. The paramedic needs blood group, allergies, current medication and
implants *now*, and needs to know the data is genuine and not stale. That is
the :class:`EmergencyDataset` — small enough for a QR code on a card.

**The mobile problem.** A patient wants their record on their phone in a train
tunnel, and wants to add to it while offline. That is the full
:class:`OfflineBundle`, plus the sync path in :mod:`ehealth.services.sync`.

What makes both work is that a bundle is **verifiable without us**. It is
signed with the ledger key, it names the ledger head it was cut from, and it
carries everything needed to check it against a published anchor. A patient
holding a bundle and a public key can prove it is authentic and unmodified with
no network, no database, and no trust in whoever handed them the file — which
is the only definition of "offline" worth having for health data.

A bundle is a *snapshot*, not a second source of truth. It says when it was
cut and when it goes stale, so a paramedic reading a two-year-old medication
list knows that is what they are looking at.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import format_spid
from ehealth.models.base import Confidentiality
from ehealth.models.clinical import (
    Dossier,
    MedicationStatement,
    MedicationStatus,
    MedicinalProduct,
)
from ehealth.models.core import Person
from ehealth.security.crypto import (
    KeyPurpose,
    KeyRing,
    Signer,
    b64u,
    b64u_decode,
    canonical_json,
    constant_time_equals,
    sha256,
)
from ehealth.services.audit import ActorContext, AuditLedger, chain_for
from ehealth.models.audit import AuditAction
from ehealth.version import version_label

#: Bundle format version. Like the audit payload, a bundle already in a
#: patient's pocket must stay verifiable after the format moves on, so readers
#: branch on this rather than assuming.
BUNDLE_VERSION = 1

#: How long an emergency dataset is considered current. Past this it still
#: verifies — it is still authentic — but readers must show it as stale,
#: because an old medication list presented as current is a clinical hazard.
DEFAULT_EMERGENCY_VALIDITY = timedelta(days=180)
DEFAULT_BUNDLE_VALIDITY = timedelta(days=30)


class OfflineError(Exception):
    pass


class BundleVerificationError(OfflineError):
    """The bundle is not authentic, or not the bundle it claims to be."""


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    """A bundle that verified, plus the judgements a reader needs.

    ``authentic`` and ``current`` are deliberately separate: an expired bundle
    is still genuine, and hiding that from a paramedic would be worse than
    showing stale data labelled as stale.
    """

    payload: dict[str, Any]
    kind: str
    subject_spid: str | None
    issued_at: datetime
    expires_at: datetime
    ledger_head: str | None
    software_version: str

    @property
    def is_current(self) -> bool:
        return utcnow() < self.expires_at

    @property
    def age(self) -> timedelta:
        return utcnow() - self.issued_at


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


class OfflineBundleService:
    """Cuts signed snapshots, and verifies them again without a database."""

    def __init__(self, keyring: KeyRing, ledger: AuditLedger, *, issuer: str) -> None:
        self._keyring = keyring
        self._ledger = ledger
        self._issuer = issuer

    def _signer(self) -> Signer:
        # Deliberately the ledger key: a bundle is an assertion about the
        # record's state, so it belongs to the same trust root as the record's
        # integrity proof, and one published public key verifies both.
        return self._keyring.signer(KeyPurpose.AUDIT_LEDGER)

    # -- building ---------------------------------------------------------

    def emergency_dataset(
        self,
        session: Session,
        *,
        patient: Person,
        dossier: Dossier,
        actor: ActorContext,
        validity: timedelta = DEFAULT_EMERGENCY_VALIDITY,
    ) -> str:
        """The small dataset a paramedic needs, signed and self-contained.

        Only ``NORMAL`` material goes in. A bundle that leaves the system
        loses every access control the system has, so anything the patient
        marked restricted or secret must not be in it — the patient chose to
        hide it, and putting it on a card they carry undoes that choice.
        """
        medications = self._current_medications(session, dossier)
        payload = {
            "v": BUNDLE_VERSION,
            "kind": "emergency",
            "iss": self._issuer,
            "subject": {
                "spid": format_spid(patient.spid) if patient.spid else None,
                "birth_date": _iso(patient.birth_date),
                "administrative_sex": patient.administrative_sex,
            },
            "medications": [
                {
                    "name": name,
                    "atc": statement.__dict__.get("_atc"),
                    "dosage": statement.dosage,
                    "since": _iso(statement.effective_start),
                }
                for statement, name in medications
            ],
            "issued_at": utcnow().isoformat(),
            "expires_at": (utcnow() + validity).isoformat(),
            "ledger_head": self._ledger_head(session, dossier.uid),
            "software_version": version_label(),
        }
        self._audit(session, actor, dossier, kind="emergency", payload=payload)
        return self.seal(payload)

    def full_bundle(
        self,
        session: Session,
        *,
        patient: Person,
        dossier: Dossier,
        actor: ActorContext,
        max_level: Confidentiality = Confidentiality.SECRET,
        validity: timedelta = DEFAULT_BUNDLE_VALIDITY,
    ) -> str:
        """The patient's own copy, for their phone.

        The patient reaches every level of their own record, so the default
        ceiling is ``SECRET`` — but the parameter exists because a bundle
        handed to someone else must be cut lower.
        """
        reachable = [
            level.value
            for level in Confidentiality
            if level.is_reachable_from(max_level)
        ]
        statements = list(
            session.execute(
                select(MedicationStatement)
                .where(
                    MedicationStatement.dossier_uid == dossier.uid,
                    MedicationStatement.confidentiality.in_(reachable),
                )
                .order_by(MedicationStatement.effective_start.desc())
            ).scalars()
        )
        payload = {
            "v": BUNDLE_VERSION,
            "kind": "dossier",
            "iss": self._issuer,
            "subject": {
                "spid": format_spid(patient.spid) if patient.spid else None,
                "birth_date": _iso(patient.birth_date),
                "administrative_sex": patient.administrative_sex,
            },
            "dossier_uid": dossier.uid,
            "max_level": max_level.value,
            "medication_statements": [
                {
                    "uid": s.uid,
                    "kind": s.kind,
                    "status": s.status,
                    "confidentiality": s.confidentiality,
                    "product_uid": s.product_uid,
                    "product_text": s.product_text,
                    "dosage": s.dosage,
                    "quantity": s.quantity,
                    "effective_start": _iso(s.effective_start),
                    "effective_end": _iso(s.effective_end),
                    "prescriber_gln": s.recorded_by_gln,
                    "version": s.version,
                }
                for s in statements
            ],
            "issued_at": utcnow().isoformat(),
            "expires_at": (utcnow() + validity).isoformat(),
            "ledger_head": self._ledger_head(session, dossier.uid),
            "software_version": version_label(),
        }
        self._audit(session, actor, dossier, kind="dossier", payload=payload)
        return self.seal(payload)

    def _current_medications(
        self, session: Session, dossier: Dossier
    ) -> list[tuple[MedicationStatement, str]]:
        now = utcnow()
        rows = list(
            session.execute(
                select(MedicationStatement, MedicinalProduct)
                .outerjoin(
                    MedicinalProduct,
                    MedicationStatement.product_uid == MedicinalProduct.uid,
                )
                .where(
                    MedicationStatement.dossier_uid == dossier.uid,
                    MedicationStatement.status == MedicationStatus.ACTIVE.value,
                    # Emergency data never carries what the patient hid.
                    MedicationStatement.confidentiality
                    == Confidentiality.NORMAL.value,
                )
                .order_by(MedicationStatement.effective_start.desc())
            )
        )
        out: list[tuple[MedicationStatement, str]] = []
        superseded = {s.based_on_uid for s, _ in rows if s.based_on_uid}
        for statement, product in rows:
            if statement.uid in superseded:
                continue
            if statement.effective_end is not None and statement.effective_end <= now:
                continue
            name = product.name if product else (statement.product_text or "unknown")
            if product is not None:
                statement.__dict__["_atc"] = product.atc_code
            out.append((statement, name))
        return out

    def _ledger_head(self, session: Session, dossier_uid: str) -> str | None:
        """The chain head this snapshot was cut from.

        Recording it is what lets a bundle be placed in the record's history:
        given a published anchor covering this head, a holder can show the
        bundle reflects a state the operator had already committed to.
        """
        head = self._ledger.head(session, chain_for(dossier_uid))
        return head.entry_hash if head else None

    def _audit(
        self,
        session: Session,
        actor: ActorContext,
        dossier: Dossier,
        *,
        kind: str,
        payload: dict[str, Any],
    ) -> None:
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.DATA_EXPORTED,
            resource_type="offline_bundle",
            dossier_uid=dossier.uid,
            detail={
                "bundle_kind": kind,
                "expires_at": payload["expires_at"],
                # The digest, so a bundle presented later can be tied to the
                # export event that produced it.
                "bundle_digest": sha256(canonical_json(payload)).hex(),
            },
        )

    # -- sealing and verifying --------------------------------------------

    def seal(self, payload: dict[str, Any]) -> str:
        """``base64url(payload).base64url(signature)`` — one line, QR-friendly."""
        body = canonical_json(payload)
        signer = self._signer()
        header = b64u(
            canonical_json({"alg": signer.algorithm, "kid": signer.kid, "typ": "BUNDLE"})
        )
        return f"{header}.{b64u(body)}.{signer.sign(sha256(body))}"

    def public_key(self) -> str:
        """The key a patient's device needs, and nothing else.

        Publish this. Verification of every bundle this system issues needs
        only this value — no API call, no account, no network.
        """
        return self._signer().public_key_b64

    def verify(self, bundle: str) -> VerifiedBundle:
        return verify_bundle(bundle, self.public_key())


# --------------------------------------------------------------------------
# Offline verification
# --------------------------------------------------------------------------


def verify_bundle(bundle: str, public_key_b64: str) -> VerifiedBundle:
    """Verify a bundle with nothing but the public key.

    Deliberately a free function with no database, no settings and no
    container: this is the code a patient's phone, a paramedic's tablet or a
    partner's system runs, and it must be portable enough to reimplement in
    any language from reading it.
    """
    import json

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    parts = (bundle or "").split(".")
    if len(parts) != 3:
        raise BundleVerificationError("a bundle has three segments")
    header_b64, body_b64, signature_b64 = parts

    try:
        header = json.loads(b64u_decode(header_b64))
        body_bytes = b64u_decode(body_b64)
        signature = b64u_decode(signature_b64)
    except Exception as exc:  # noqa: BLE001 - normalise to our error type
        raise BundleVerificationError("bundle is malformed") from exc

    if header.get("typ") != "BUNDLE":
        raise BundleVerificationError("not a bundle")
    if header.get("alg") != "Ed25519":
        # Closed algorithm set, same as everywhere else: no negotiation, no
        # "none", no downgrade.
        raise BundleVerificationError(f"unsupported algorithm {header.get('alg')!r}")

    try:
        Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64)).verify(
            signature, sha256(body_bytes)
        )
    except (InvalidSignature, ValueError) as exc:
        raise BundleVerificationError("signature does not verify") from exc

    try:
        payload = json.loads(body_bytes)
    except ValueError as exc:
        raise BundleVerificationError("bundle body is not JSON") from exc
    if not isinstance(payload, dict):
        raise BundleVerificationError("bundle body must be an object")

    if payload.get("v") != BUNDLE_VERSION:
        raise BundleVerificationError(
            f"bundle format version {payload.get('v')!r} is not supported by this "
            f"reader"
        )
    # The signature covers the canonical form, so a re-encoded body with the
    # same values still verifies but a *reordered or padded* one that changed
    # any value does not.
    if not constant_time_equals(canonical_json(payload), body_bytes):
        raise BundleVerificationError("bundle body is not in canonical form")

    try:
        issued_at = datetime.fromisoformat(payload["issued_at"])
        expires_at = datetime.fromisoformat(payload["expires_at"])
    except (KeyError, ValueError) as exc:
        raise BundleVerificationError("bundle timestamps are missing or malformed") from exc
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=UTC)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    return VerifiedBundle(
        payload=payload,
        kind=payload.get("kind", "unknown"),
        subject_spid=(payload.get("subject") or {}).get("spid"),
        issued_at=issued_at,
        expires_at=expires_at,
        ledger_head=payload.get("ledger_head"),
        software_version=payload.get("software_version", "unknown"),
    )
