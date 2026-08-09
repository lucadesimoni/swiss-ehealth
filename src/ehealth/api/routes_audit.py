# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Audit trail, record history and ledger integrity.

This is the patient's window onto who touched their record (EPDV art. 17) and
the operator's proof that the trail has not been rewritten.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, status
from sqlalchemy import select

from ehealth.api.deps import ContainerDep, CurrentUserDep, DbDep
from ehealth.api.routes_auth import AdminKeyDep
from ehealth.api.schemas import (
    AuditEventOut,
    ChainVerificationOut,
    LedgerVerificationOut,
    RevisionOut,
)
from ehealth.db import utcnow
from ehealth.models.audit import AuditEvent
from ehealth.security.crypto import SIGNATURE_ALGORITHMS
from ehealth.security.tokens import Scope
from ehealth.services.audit import GLOBAL_CHAIN, PAYLOAD_BUILDERS
from ehealth.version import release_identity

router = APIRouter(tags=["audit"])


def _event_out(event: AuditEvent) -> AuditEventOut:
    return AuditEventOut(
        seq=event.seq,
        uid=event.uid,
        occurred_at=event.occurred_at,
        actor_uid=event.actor_uid,
        actor_kind=event.actor_kind,
        on_behalf_of_uid=event.on_behalf_of_uid,
        action=event.action,
        outcome=event.outcome,
        purpose=event.purpose,
        resource_type=event.resource_type,
        resource_uid=event.resource_uid,
        dossier_uid=event.dossier_uid,
        token_jti=event.token_jti,
        detail=event.detail,
        entry_hash=event.entry_hash,
        chain_id=event.chain_id,
        payload_version=event.payload_version,
        software_version=event.software_version,
    )


@router.get("/audit/me", response_model=list[AuditEventOut])
def own_audit_trail(
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    since: Annotated[datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    """Every access to the caller's own dossier.

    Answering this well is the whole point of the ledger: a patient who cannot
    see who read their record has no way to notice misuse.
    """
    user.require_scope(Scope.AUDIT_READ)
    dossier = container.dossiers.for_patient(db, user.claims.subject_uid)
    if dossier is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    stmt = select(AuditEvent).where(AuditEvent.dossier_uid == dossier.uid)
    if since is not None:
        stmt = stmt.where(AuditEvent.occurred_at >= since)
    events = db.execute(stmt.order_by(AuditEvent.seq.desc()).limit(limit)).scalars()
    return [_event_out(event) for event in events]


@router.get(
    "/audit/verify", response_model=ChainVerificationOut, dependencies=[AdminKeyDep]
)
def verify_chain(
    db: DbDep,
    container: ContainerDep,
    chain_id: Annotated[str, Query(max_length=32)] = GLOBAL_CHAIN,
    start_seq: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int | None, Query(ge=1, le=100_000)] = None,
):
    """Recompute one chain's links and signatures.

    ``chain_id`` is a dossier UID, or ``global`` for everything not scoped to
    a patient. Verifying a single dossier is the question a patient actually
    has ("was *my* record tampered with"), and it stays cheap however large
    the system gets.
    """
    result = container.ledger.verify_chain(
        db, chain_id, start_seq=start_seq, limit=limit
    )
    return ChainVerificationOut(
        ok=result.ok,
        checked=result.checked,
        first_bad_seq=result.first_bad_seq,
        reason=result.reason,
        chain_id=result.chain_id,
    )


@router.get(
    "/audit/verify-all",
    response_model=LedgerVerificationOut,
    dependencies=[AdminKeyDep],
)
def verify_all(
    db: DbDep,
    container: ContainerDep,
    max_chains: Annotated[int | None, Query(ge=1, le=100_000)] = None,
):
    """Verify every chain. A background job at scale, not a request."""
    result = container.ledger.verify_all(db, max_chains=max_chains)
    return LedgerVerificationOut(
        ok=result.ok,
        chains_checked=result.chains_checked,
        events_checked=result.events_checked,
        failures=[
            ChainVerificationOut(
                ok=f.ok,
                checked=f.checked,
                first_bad_seq=f.first_bad_seq,
                reason=f.reason,
                chain_id=f.chain_id,
            )
            for f in result.failures
        ],
    )


@router.post("/audit/anchor", dependencies=[AdminKeyDep])
def anchor_ledger(
    db: DbDep,
    container: ContainerDep,
    period: Annotated[str | None, Query(max_length=24)] = None,
):
    """Seal the ledger head for a period.

    Publishing the returned head hash somewhere outside the operator's control
    is what turns "we would notice tampering" into "we can prove there was
    none up to this point".
    """
    period = period or utcnow().date().isoformat()
    try:
        anchor = container.ledger.anchor(db, period)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return {
        "period": anchor.period,
        # The value to publish externally. Once it is somewhere the operator
        # cannot rewrite, everything up to it is frozen.
        "anchor_hash": anchor.anchor_hash,
        "merkle_root": anchor.merkle_root,
        "previous_anchor_hash": anchor.previous_anchor_hash,
        "chain_count": anchor.chain_count,
        "event_count": anchor.event_count,
        "signature": anchor.signature,
        "key_id": anchor.key_id,
        "algorithm": anchor.algorithm,
        "software_version": anchor.software_version,
        "verified": container.ledger.verify_anchor(db, anchor),
    }


@router.get("/version", tags=["operations"], dependencies=[AdminKeyDep])
def software_version(container: ContainerDep):
    """What exactly is running here.

    Behind the admin key rather than public: build provenance is what an
    auditor needs and what an attacker uses to pick a known vulnerability, and
    the people entitled to the first already hold the key.

    ``revision`` matches a git commit, ``label`` matches the
    ``software_version`` stamped on every ledger entry, so a record can be
    traced to the code that wrote it.
    """
    identity = release_identity()
    return {
        **identity.as_dict(),
        "signature_algorithms": {
            name: {"issuing": algorithm.issuing, "available": algorithm.available}
            for name, algorithm in SIGNATURE_ALGORITHMS.items()
        },
        "audit_payload_versions_supported": sorted(PAYLOAD_BUILDERS),
        "data_region": container.settings.data_region.value,
        "environment": container.settings.environment.value,
    }


@router.get(
    "/history/{entity_type}/{entity_uid}",
    response_model=list[RevisionOut],
    dependencies=[AdminKeyDep],
)
def record_history(
    entity_type: Annotated[str, Path(max_length=40)],
    entity_uid: Annotated[str, Path(max_length=32)],
    db: DbDep,
    container: ContainerDep,
):
    """Full version history of one row, newest last."""
    revisions = container.tracker.history(db, entity_type, entity_uid)
    if not revisions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return [
        RevisionOut(
            uid=revision.uid,
            entity_type=revision.entity_type,
            entity_uid=revision.entity_uid,
            version=revision.version,
            operation=revision.operation,
            changed_by_uid=revision.changed_by_uid,
            changed_at=revision.changed_at,
            valid_from=revision.valid_from,
            valid_until=revision.valid_until,
            diff=revision.diff,
            state_hash=revision.state_hash,
            audit_seq=revision.audit_seq,
            reason=revision.reason,
        )
        for revision in revisions
    ]
