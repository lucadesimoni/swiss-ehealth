# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Syncing back what a patient captured while offline.

The hard part of offline is not going offline, it is coming back. Three things
have to be true or patients quietly lose data and stop trusting the app:

**Retries must not duplicate.** A phone that loses signal mid-upload will send
the batch again. Every item carries a client-generated id (a ULID, so it needs
no coordination with us), and that id is the idempotency key: the second
attempt returns the row the first one created.

**Partial success must be reportable.** A batch of twelve where one item names
a withdrawn product must apply the other eleven and say precisely what happened
to the twelfth. All-or-nothing would mean one bad row blocks a patient's whole
history, and silent dropping is worse.

**The device clock is not evidence.** A phone's clock can be wrong, or set by
someone with a reason. The captured time is recorded because it is clinically
meaningful, and the server's own clock is what orders the record. Both are
kept; only one is trusted.

Clinical facts are append-only, so there is nothing to merge — two devices
recording the same dose produce two entries with different client ids, and
reconciliation is a clinical judgement, not a database one. What this module
refuses to do is guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.models.audit import AuditAction
from ehealth.models.clinical import MedicationEventKind, MedicationStatement
from ehealth.services.access import AuthorizedAccess
from ehealth.services.audit import AuditLedger
from ehealth.services.medication import (
    MedicationError,
    MedicationService,
    StatementInput,
)

#: How far a client clock may be ahead before the capture time is rejected.
#: Behind is tolerated generously — that is just a phone that was off — but
#: the future is not a place data can be captured in.
MAX_CLOCK_SKEW_AHEAD = timedelta(hours=1)

#: A device that has been offline for longer than this is asked to re-sync from
#: scratch rather than replaying a very old queue.
MAX_CAPTURE_AGE = timedelta(days=365)

#: Cap on one batch, so a broken client cannot turn a sync into an outage.
MAX_BATCH_ITEMS = 500

#: What a patient's own device may record while offline. Prescribing needs a
#: licensed professional and a live licence check, neither of which can happen
#: on a phone in a tunnel.
OFFLINE_CAPTURABLE_KINDS = frozenset(
    {MedicationEventKind.SELF_REPORTED, MedicationEventKind.ADMINISTRATION}
)


class SyncOutcome(StrEnum):
    APPLIED = "applied"
    #: Already applied under this client id — the retry case, not an error.
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


class SyncError(Exception):
    pass


@dataclass(slots=True)
class OfflineCapture:
    """One thing a patient recorded on their device."""

    #: Client-generated, stable across retries. The idempotency key.
    client_uid: str
    statement: StatementInput
    #: The device's clock at capture. Recorded, never trusted for ordering.
    captured_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class SyncResult:
    client_uid: str
    outcome: SyncOutcome
    statement_uid: str | None = None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class SyncReport:
    results: tuple[SyncResult, ...] = field(default=())

    @property
    def applied(self) -> int:
        return sum(1 for r in self.results if r.outcome is SyncOutcome.APPLIED)

    @property
    def duplicates(self) -> int:
        return sum(1 for r in self.results if r.outcome is SyncOutcome.DUPLICATE)

    @property
    def rejected(self) -> int:
        return sum(1 for r in self.results if r.outcome is SyncOutcome.REJECTED)


class OfflineSyncService:
    def __init__(self, medications: MedicationService, ledger: AuditLedger) -> None:
        self._medications = medications
        self._ledger = ledger

    def apply(
        self,
        session: Session,
        access: AuthorizedAccess,
        captures: list[OfflineCapture],
        *,
        recorded_by_uid: str,
    ) -> SyncReport:
        """Apply a batch, reporting per item.

        Each item is applied in its own savepoint, so one rejection does not
        roll back the rest of the batch — which is the whole point of
        reporting per item rather than per batch.
        """
        if len(captures) > MAX_BATCH_ITEMS:
            raise SyncError(f"a batch may carry at most {MAX_BATCH_ITEMS} items")

        seen: set[str] = set()
        results: list[SyncResult] = []
        for capture in captures:
            if capture.client_uid in seen:
                # Duplicated *within* the batch — a client bug, but the
                # answer is the same as any other retry.
                results.append(SyncResult(capture.client_uid, SyncOutcome.DUPLICATE))
                continue
            seen.add(capture.client_uid)
            results.append(self._apply_one(session, access, capture, recorded_by_uid))

        report = SyncReport(tuple(results))
        self._ledger.append(
            session,
            actor=access.actor,
            action=AuditAction.MEDICATION_ADDED,
            resource_type="offline_sync",
            dossier_uid=access.dossier_uid,
            detail={
                "items": len(captures),
                "applied": report.applied,
                "duplicates": report.duplicates,
                "rejected": report.rejected,
            },
        )
        return report

    def _apply_one(
        self,
        session: Session,
        access: AuthorizedAccess,
        capture: OfflineCapture,
        recorded_by_uid: str,
    ) -> SyncResult:
        existing = self.find_by_client_uid(
            session, access.dossier_uid, capture.client_uid
        )
        if existing is not None:
            return SyncResult(
                capture.client_uid, SyncOutcome.DUPLICATE, statement_uid=existing.uid
            )

        try:
            captured_at = self._check_capture_time(capture.captured_at)
            if capture.statement.kind not in OFFLINE_CAPTURABLE_KINDS:
                raise SyncError(
                    f"{capture.statement.kind.value} cannot be captured offline"
                )
        except SyncError as exc:
            return SyncResult(capture.client_uid, SyncOutcome.REJECTED, reason=str(exc))

        # A savepoint per item: a rejection undoes only that item's partial
        # writes, and the rest of the batch still lands.
        savepoint = session.begin_nested()
        try:
            statement = self._medications.record(
                session,
                access,
                capture.statement,
                recorded_by_uid=recorded_by_uid,
            )
            statement.offline_client_uid = capture.client_uid
            statement.captured_offline_at = captured_at
            session.flush()
        except (MedicationError, SyncError) as exc:
            savepoint.rollback()
            return SyncResult(capture.client_uid, SyncOutcome.REJECTED, reason=str(exc))
        savepoint.commit()
        return SyncResult(
            capture.client_uid, SyncOutcome.APPLIED, statement_uid=statement.uid
        )

    @staticmethod
    def _check_capture_time(captured_at: datetime | None) -> datetime | None:
        if captured_at is None:
            return None
        if captured_at.tzinfo is None:
            raise SyncError("captured_at must carry a timezone")
        now = utcnow()
        if captured_at > now + MAX_CLOCK_SKEW_AHEAD:
            raise SyncError("captured_at is in the future")
        if captured_at < now - MAX_CAPTURE_AGE:
            raise SyncError("captured_at is too old; re-sync from scratch")
        return captured_at

    @staticmethod
    def find_by_client_uid(
        session: Session, dossier_uid: str, client_uid: str
    ) -> MedicationStatement | None:
        return (
            session.execute(
                select(MedicationStatement).where(
                    MedicationStatement.dossier_uid == dossier_uid,
                    MedicationStatement.offline_client_uid == client_uid,
                )
            )
            .scalars()
            .first()
        )

    @staticmethod
    def changes_since(
        session: Session, dossier_uid: str, since: datetime | None, *, limit: int = 500
    ) -> list[MedicationStatement]:
        """What the device missed while it was away.

        Ordered by the *server's* clock, which is the one that defines the
        record's order — a device that was offline for a week cannot know where
        its entries belong relative to a clinician's.
        """
        stmt = select(MedicationStatement).where(
            MedicationStatement.dossier_uid == dossier_uid
        )
        if since is not None:
            stmt = stmt.where(MedicationStatement.updated_at > since)
        return list(
            session.execute(
                stmt.order_by(MedicationStatement.updated_at).limit(min(limit, 500))
            ).scalars()
        )
