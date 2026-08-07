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
from ehealth.api.schemas import AuditEventOut, ChainVerificationOut, RevisionOut
from ehealth.db import utcnow
from ehealth.models.audit import AuditEvent
from ehealth.security.tokens import Scope

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
    events = db.execute(
        stmt.order_by(AuditEvent.seq.desc()).limit(limit)
    ).scalars()
    return [_event_out(event) for event in events]


@router.get(
    "/audit/verify", response_model=ChainVerificationOut, dependencies=[AdminKeyDep]
)
def verify_chain(
    db: DbDep,
    container: ContainerDep,
    start_seq: Annotated[int, Query(ge=1)] = 1,
    limit: Annotated[int | None, Query(ge=1, le=100_000)] = None,
):
    """Recompute the hash chain and every signature over a range."""
    result = container.ledger.verify_chain(db, start_seq=start_seq, limit=limit)
    return ChainVerificationOut(
        ok=result.ok,
        checked=result.checked,
        first_bad_seq=result.first_bad_seq,
        reason=result.reason,
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
        "first_seq": anchor.first_seq,
        "last_seq": anchor.last_seq,
        "head_hash": anchor.head_hash,
        "event_count": anchor.event_count,
        "signature": anchor.signature,
        "key_id": anchor.key_id,
        "algorithm": anchor.algorithm,
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
