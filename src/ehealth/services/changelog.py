"""Per-record change tracking.

Wraps every mutation so that three things happen together or not at all:

1. the row changes and its ``version`` increments,
2. a :class:`~ehealth.models.audit.RecordRevision` captures the diff and a
   hash of the resulting state,
3. an :class:`~ehealth.models.audit.AuditEvent` records who did it and why.

Fields listed in :data:`PROTECTED_FIELDS` never appear in a diff as plaintext.
A change history that faithfully recorded "family_name_enc changed from X to
Y" would quietly become a second, unprotected copy of the record — so those
fields are reduced to a hash, which still proves *that* they changed and lets
two versions be compared, without restating the content.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import new_uid
from ehealth.models.audit import (
    AuditAction,
    AuditOutcome,
    ChangeOperation,
    RecordRevision,
)
from ehealth.security.crypto import canonical_json, sha256
from ehealth.services.audit import ActorContext, AuditLedger

#: Column name suffixes and exact names whose values are never written into a
#: diff in the clear.
PROTECTED_SUFFIXES = ("_enc",)
PROTECTED_FIELDS = frozenset(
    {
        "sealed_ahvn",
        "ppid",
        "lookup_index",
        "email_index",
        "code_hash",
        "storage_ref",
    }
)

#: Columns that are bookkeeping rather than content; changing them alone is
#: not a change worth a revision row.
IGNORED_FIELDS = frozenset({"created_at", "updated_at", "version"})


def is_protected(field: str) -> bool:
    return field in PROTECTED_FIELDS or field.endswith(PROTECTED_SUFFIXES)


def _redact(field: str, value: Any) -> Any:
    if value is None:
        return None
    if is_protected(field):
        return {"sha256": sha256(str(value).encode("utf-8")).hex()[:32]}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


def snapshot(entity: Any) -> dict[str, Any]:
    """Serialisable view of a mapped row, with protected fields redacted."""
    columns = entity.__table__.columns.keys()
    return {
        name: _redact(name, getattr(entity, name))
        for name in columns
        if name not in IGNORED_FIELDS
    }


def diff_states(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    changed: dict[str, Any] = {}
    for field in sorted(set(before) | set(after)):
        old, new = before.get(field), after.get(field)
        if old != new:
            changed[field] = {"from": old, "to": new}
    return changed


def state_hash(entity: Any) -> str:
    """Hash of the row's full state, including protected fields' hashes.

    Two versions with the same state hash are byte-identical in every tracked
    column, which is what makes a replayed history checkable.
    """
    return sha256(canonical_json(snapshot(entity))).hex()


class ChangeTracker:
    """Records revisions and closes out the previous one's validity window."""

    def __init__(self, ledger: AuditLedger) -> None:
        self._ledger = ledger

    def record_create(
        self,
        session: Session,
        entity: Any,
        *,
        actor: ActorContext,
        action: AuditAction,
        dossier_uid: str | None = None,
        detail: dict | None = None,
        reason: str | None = None,
    ) -> RecordRevision:
        entity.version = 1
        return self._write(
            session,
            entity,
            operation=ChangeOperation.CREATE,
            diff={
                field: {"from": None, "to": value}
                for field, value in snapshot(entity).items()
                if value is not None
            },
            actor=actor,
            action=action,
            dossier_uid=dossier_uid,
            detail=detail,
            reason=reason,
        )

    def record_update(
        self,
        session: Session,
        entity: Any,
        before: dict[str, Any],
        *,
        actor: ActorContext,
        action: AuditAction,
        operation: ChangeOperation = ChangeOperation.UPDATE,
        dossier_uid: str | None = None,
        detail: dict | None = None,
        reason: str | None = None,
    ) -> RecordRevision | None:
        """Record a change. Returns ``None`` when nothing actually changed.

        Callers capture ``before`` with :func:`snapshot` prior to mutating.
        No-op updates produce no revision and no audit noise, which keeps the
        history meaningful.
        """
        changes = diff_states(before, snapshot(entity))
        if not changes:
            return None
        entity.version = (entity.version or 1) + 1
        return self._write(
            session,
            entity,
            operation=operation,
            diff=changes,
            actor=actor,
            action=action,
            dossier_uid=dossier_uid,
            detail=detail,
            reason=reason,
        )

    def _write(
        self,
        session: Session,
        entity: Any,
        *,
        operation: ChangeOperation,
        diff: dict[str, Any],
        actor: ActorContext,
        action: AuditAction,
        dossier_uid: str | None,
        detail: dict | None,
        reason: str | None,
    ) -> RecordRevision:
        entity_type = entity.__tablename__
        entity_uid = entity.uid
        now = utcnow()

        event = self._ledger.append(
            session,
            actor=actor,
            action=action,
            resource_type=entity_type,
            resource_uid=entity_uid,
            dossier_uid=dossier_uid,
            outcome=AuditOutcome.SUCCESS,
            detail={
                **(detail or {}),
                "version": entity.version,
                "changed_fields": sorted(diff),
            },
            occurred_at=now,
        )

        # Close the previous revision's validity window so exactly one
        # revision is current for any given instant.
        session.execute(
            update(RecordRevision)
            .where(
                RecordRevision.entity_type == entity_type,
                RecordRevision.entity_uid == entity_uid,
                RecordRevision.valid_until.is_(None),
            )
            .values(valid_until=now)
        )

        revision = RecordRevision(
            uid=new_uid("req"),
            entity_type=entity_type,
            entity_uid=entity_uid,
            version=entity.version,
            operation=operation.value,
            changed_by_uid=actor.actor_uid,
            changed_at=now,
            valid_from=now,
            valid_until=None,
            diff=diff,
            state_hash=state_hash(entity),
            audit_seq=event.seq,
            reason=reason,
        )
        session.add(revision)
        session.flush()
        return revision

    # -- reading history --------------------------------------------------

    @staticmethod
    def history(
        session: Session, entity_type: str, entity_uid: str
    ) -> list[RecordRevision]:
        return list(
            session.execute(
                select(RecordRevision)
                .where(
                    RecordRevision.entity_type == entity_type,
                    RecordRevision.entity_uid == entity_uid,
                )
                .order_by(RecordRevision.version)
            ).scalars()
        )

    @staticmethod
    def version_at(
        session: Session, entity_type: str, entity_uid: str, instant: datetime
    ) -> RecordRevision | None:
        """The revision that was current at ``instant``."""
        return (
            session.execute(
                select(RecordRevision)
                .where(
                    RecordRevision.entity_type == entity_type,
                    RecordRevision.entity_uid == entity_uid,
                    RecordRevision.valid_from <= instant,
                )
                .order_by(RecordRevision.valid_from.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )

    @staticmethod
    def replay(revisions: Iterable[RecordRevision]) -> dict[str, Any]:
        """Rebuild a row's tracked state by applying diffs in order."""
        state: dict[str, Any] = {}
        for revision in revisions:
            for field, change in revision.diff.items():
                state[field] = change["to"]
        return state
