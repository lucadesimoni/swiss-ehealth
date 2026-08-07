# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Offline endpoints: take the record with you, bring changes back."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ehealth.api.deps import ContainerDep, CurrentUserDep, DbDep, capability_access
from ehealth.api.schemas import (
    BundleOut,
    OfflineSyncIn,
    PublicKeyOut,
    SyncReportOut,
    SyncResultOut,
)
from ehealth.models.base import Confidentiality
from ehealth.models.clinical import MedicationEventKind
from ehealth.security.tokens import Scope
from ehealth.services.access import AuthorizedAccess
from ehealth.services.medication import StatementInput
from ehealth.services.sync import OfflineCapture, SyncError

router = APIRouter(tags=["offline"])

BundleAccess = Annotated[
    AuthorizedAccess, Depends(capability_access(Scope.DOSSIER_READ))
]
SyncAccess = Annotated[
    AuthorizedAccess, Depends(capability_access(Scope.MEDICATION_WRITE))
]


@router.get("/offline/public-key", response_model=PublicKeyOut)
def bundle_public_key(container: ContainerDep):
    """The key that verifies every bundle this system issues.

    Deliberately public and unauthenticated: a patient's device, a paramedic's
    tablet or a partner system must be able to check a bundle with no account
    and no network path back to us. That is what makes the bundles genuinely
    offline rather than merely downloadable.
    """
    return PublicKeyOut(
        algorithm="Ed25519",
        public_key=container.offline.public_key(),
        bundle_format_version=1,
    )


@router.post("/offline/emergency-dataset", response_model=BundleOut)
def emergency_dataset(
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    access: BundleAccess,
    validity_days: Annotated[int, Query(ge=1, le=730)] = 180,
):
    """The small signed dataset for a card, a wallet or a QR code.

    Carries only material the patient left at the NORMAL level: a bundle that
    leaves the system loses every access control the system has, so anything
    the patient chose to restrict must not travel on a card they carry.
    """
    from datetime import timedelta

    patient = container.persons.get(db, user.claims.subject_uid)
    dossier = container.dossiers.for_patient(db, patient.uid)
    if dossier is None or dossier.uid != access.dossier_uid:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    bundle = container.offline.emergency_dataset(
        db,
        patient=patient,
        dossier=dossier,
        actor=access.actor,
        validity=timedelta(days=validity_days),
    )
    verified = container.offline.verify(bundle)
    return BundleOut(
        bundle=bundle,
        kind=verified.kind,
        issued_at=verified.issued_at,
        expires_at=verified.expires_at,
        ledger_head=verified.ledger_head,
        size_bytes=len(bundle),
    )


@router.post("/offline/bundle", response_model=BundleOut)
def full_bundle(
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    access: BundleAccess,
    validity_days: Annotated[int, Query(ge=1, le=365)] = 30,
):
    """The patient's own copy of their record, for their device."""
    from datetime import timedelta

    patient = container.persons.get(db, user.claims.subject_uid)
    dossier = container.dossiers.for_patient(db, patient.uid)
    if dossier is None or dossier.uid != access.dossier_uid:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    bundle = container.offline.full_bundle(
        db,
        patient=patient,
        dossier=dossier,
        actor=access.actor,
        # Clamped to what the capability actually reaches, so a bundle can
        # never carry more than the token that asked for it.
        max_level=access.max_level,
        validity=timedelta(days=validity_days),
    )
    verified = container.offline.verify(bundle)
    return BundleOut(
        bundle=bundle,
        kind=verified.kind,
        issued_at=verified.issued_at,
        expires_at=verified.expires_at,
        ledger_head=verified.ledger_head,
        size_bytes=len(bundle),
    )


@router.post("/offline/sync", response_model=SyncReportOut)
def sync_offline_captures(
    payload: OfflineSyncIn,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    access: SyncAccess,
):
    """Upload what was captured while offline.

    Idempotent per ``client_uid`` and reported per item: a retried batch
    returns ``duplicate`` for what already landed, and one bad row never blocks
    the rest.
    """
    captures = [
        OfflineCapture(
            client_uid=item.client_uid,
            captured_at=item.captured_at,
            statement=StatementInput(
                kind=MedicationEventKind(item.kind),
                product_uid=item.product_uid,
                product_text=item.product_text,
                dosage=item.dosage,
                quantity=item.quantity,
                reason=item.reason,
                effective_start=item.effective_start,
                effective_end=item.effective_end,
                confidentiality=Confidentiality(item.confidentiality),
            ),
        )
        for item in payload.items
    ]
    try:
        report = container.sync.apply(
            db, access, captures, recorded_by_uid=user.claims.subject_uid
        )
    except SyncError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return SyncReportOut(
        applied=report.applied,
        duplicates=report.duplicates,
        rejected=report.rejected,
        results=[
            SyncResultOut(
                client_uid=r.client_uid,
                outcome=r.outcome.value,
                statement_uid=r.statement_uid,
                reason=r.reason,
            )
            for r in report.results
        ],
    )
