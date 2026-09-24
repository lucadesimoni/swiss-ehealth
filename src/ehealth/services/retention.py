# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Retention: destroy a dossier's health data once its period has passed.

EPDV art. 10: data in the electronic patient record is kept for twenty years
and then destroyed. ``Dossier.retention_until`` holds that horizon and every
write pushes it out; this job acts on it.

What is destroyed, and what deliberately is not:

* **Destroyed:** document contents (the encrypted blobs), document titles,
  medication free text (product text, dosage, quantity, reason), and the
  per-field *values* in the change history of those rows — a change history
  that kept the old title would be a second copy of the thing destroyed.
* **Kept:** the dossier shell (status ``archived``), each row's identity,
  type and timestamps, and **the audit ledger, unchanged**. The ledger records
  who did what and when, not the clinical content; it is hash-chained and
  signed, and editing it would make every later entry unverifiable. Its
  retention is a separate decision, recorded in ``docs/compliance.md``.

Runs as a dry run unless told otherwise, and records one ``data.retention_
applied`` event per dossier in the global chain, with counts and nothing
clinical.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.models.audit import AuditAction, RecordRevision
from ehealth.models.clinical import (
    Dossier,
    DossierDocument,
    DossierStatus,
    MedicationStatement,
)
from ehealth.services.audit import ActorContext, AuditLedger
from ehealth.services.blobstore import DocumentContentStore

PURGED = "[destroyed after retention period]"


@dataclass(frozen=True, slots=True)
class RetentionResult:
    dossier_uid: str
    documents: int
    medications: int
    revisions: int
    applied: bool


class RetentionService:
    def __init__(
        self, ledger: AuditLedger, content: DocumentContentStore | None
    ) -> None:
        self._ledger = ledger
        self._content = content

    @staticmethod
    def due(session: Session, *, now: datetime | None = None) -> list[Dossier]:
        now = now or utcnow()
        return list(
            session.execute(
                select(Dossier).where(
                    Dossier.retention_until.is_not(None),
                    Dossier.retention_until <= now,
                    Dossier.status != DossierStatus.ARCHIVED.value,
                )
            ).scalars()
        )

    def apply(
        self,
        session: Session,
        actor: ActorContext,
        *,
        now: datetime | None = None,
        dry_run: bool = True,
    ) -> list[RetentionResult]:
        return [
            self._destroy(session, actor, dossier, dry_run=dry_run)
            for dossier in self.due(session, now=now)
        ]

    def _destroy(
        self, session: Session, actor: ActorContext, dossier: Dossier, *, dry_run: bool
    ) -> RetentionResult:
        documents = list(
            session.execute(
                select(DossierDocument).where(
                    DossierDocument.dossier_uid == dossier.uid
                )
            ).scalars()
        )
        medications = list(
            session.execute(
                select(MedicationStatement).where(
                    MedicationStatement.dossier_uid == dossier.uid
                )
            ).scalars()
        )
        entity_uids = [d.uid for d in documents] + [m.uid for m in medications]
        revisions = (
            list(
                session.execute(
                    select(RecordRevision).where(
                        RecordRevision.entity_uid.in_(entity_uids)
                    )
                ).scalars()
            )
            if entity_uids
            else []
        )
        result = RetentionResult(
            dossier.uid, len(documents), len(medications), len(revisions), not dry_run
        )
        if dry_run:
            return result

        for document in documents:
            if self._content is not None and (document.storage_ref or "").startswith(
                "blob:"
            ):
                self._content.destroy(document.uid)
            document.title = PURGED
            document.storage_ref = None
        for statement in medications:
            statement.product_text = None
            statement.dosage = {}
            statement.quantity = None
            statement.reason = None
        for revision in revisions:
            # Which fields changed stays answerable; what they held does not.
            revision.diff = {field: {"purged": True} for field in revision.diff}
        dossier.status = DossierStatus.ARCHIVED.value
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.RETENTION_APPLIED,
            resource_type="dossier",
            resource_uid=dossier.uid,
            detail={
                "documents": result.documents,
                "medications": result.medications,
                "revisions": result.revisions,
                "retention_until": dossier.retention_until.isoformat()
                if dossier.retention_until
                else None,
            },
        )
        return result
