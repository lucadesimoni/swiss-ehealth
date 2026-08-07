"""Dossier and document operations.

Reads are audited as carefully as writes. A record system where "who looked at
this" is unanswerable fails the patient's right to know under EPDV art. 17,
so every retrieval here goes through the ledger.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import new_uid
from ehealth.models.audit import AuditAction, ChangeOperation
from ehealth.models.base import Confidentiality
from ehealth.models.clinical import (
    DocumentStatus,
    Dossier,
    DossierDocument,
    DossierStatus,
)
from ehealth.models.core import Person
from ehealth.services.access import AuthorizedAccess
from ehealth.services.audit import ActorContext, AuditLedger
from ehealth.services.changelog import ChangeTracker, snapshot


class DossierError(Exception):
    pass


@dataclass(slots=True)
class DocumentInput:
    title: str
    document_class: str
    mime_type: str
    content: bytes
    confidentiality: Confidentiality = Confidentiality.NORMAL
    language: str = "de-CH"
    storage_ref: str | None = None
    supersedes_uid: str | None = None
    service_start: datetime | None = None
    service_end: datetime | None = None


class DossierService:
    def __init__(
        self,
        ledger: AuditLedger,
        tracker: ChangeTracker,
        *,
        retention_years: int = 20,
    ) -> None:
        self._ledger = ledger
        self._tracker = tracker
        self._retention_years = retention_years

    # -- lifecycle --------------------------------------------------------

    def open(
        self,
        session: Session,
        actor: ActorContext,
        *,
        patient: Person,
        home_community: str | None = None,
        default_confidentiality: Confidentiality = Confidentiality.NORMAL,
    ) -> Dossier:
        if not patient.is_patient():
            raise DossierError("only a patient can have a dossier")
        existing = self.for_patient(session, patient.uid)
        if existing is not None:
            raise DossierError("this patient already has a dossier")
        now = utcnow()
        dossier = Dossier(
            uid=new_uid("dos"),
            patient_uid=patient.uid,
            status=DossierStatus.ACTIVE.value,
            opened_at=now,
            retention_until=self._retention_horizon(now),
            default_confidentiality=default_confidentiality.value,
            home_community=home_community,
        )
        session.add(dossier)
        session.flush()
        self._tracker.record_create(
            session,
            dossier,
            actor=actor,
            action=AuditAction.DOSSIER_OPENED,
            dossier_uid=dossier.uid,
            detail={"patient_uid": patient.uid},
        )
        return dossier

    def _retention_horizon(self, from_instant: datetime) -> datetime:
        # timedelta has no "years"; 365.2425 days is the mean Gregorian year
        # and is accurate enough for a 20 year horizon.
        return from_instant + timedelta(days=365.2425 * self._retention_years)

    @staticmethod
    def for_patient(session: Session, patient_uid: str) -> Dossier | None:
        return (
            session.execute(select(Dossier).where(Dossier.patient_uid == patient_uid))
            .scalars()
            .first()
        )

    @staticmethod
    def get(session: Session, dossier_uid: str) -> Dossier:
        dossier = session.get(Dossier, dossier_uid)
        if dossier is None:
            raise DossierError("unknown dossier")
        return dossier

    def close(
        self, session: Session, actor: ActorContext, dossier: Dossier, *, reason: str
    ) -> Dossier:
        before = snapshot(dossier)
        dossier.status = DossierStatus.CLOSED.value
        dossier.closed_at = utcnow()
        self._tracker.record_update(
            session,
            dossier,
            before,
            actor=actor,
            action=AuditAction.DOSSIER_CLOSED,
            operation=ChangeOperation.STATUS_CHANGE,
            dossier_uid=dossier.uid,
            reason=reason,
        )
        return dossier

    # -- documents --------------------------------------------------------

    def add_document(
        self,
        session: Session,
        access: AuthorizedAccess,
        *,
        author: Person,
        document: DocumentInput,
    ) -> DossierDocument:
        """Add a document. The author's own confidentiality choice is honoured
        upward but never downward past what the dossier defaults to."""
        dossier = self.get(session, access.dossier_uid)
        if dossier.status != DossierStatus.ACTIVE.value:
            raise DossierError("dossier is not active")

        content_hash = hashlib.sha256(document.content).hexdigest()
        record = DossierDocument(
            uid=new_uid("doc"),
            dossier_uid=dossier.uid,
            title=document.title,
            document_class=document.document_class,
            mime_type=document.mime_type,
            language=document.language,
            confidentiality=document.confidentiality.value,
            status=DocumentStatus.CURRENT.value,
            author_uid=author.uid,
            author_organization_uid=author.organization_uid,
            content_hash=content_hash,
            content_size=len(document.content),
            storage_ref=document.storage_ref,
            supersedes_uid=document.supersedes_uid,
            service_start=document.service_start,
            service_end=document.service_end,
        )
        session.add(record)
        session.flush()

        if document.supersedes_uid:
            previous = session.get(DossierDocument, document.supersedes_uid)
            if previous is None or previous.dossier_uid != dossier.uid:
                raise DossierError("superseded document does not belong to this dossier")
            previous_before = snapshot(previous)
            previous.status = DocumentStatus.SUPERSEDED.value
            self._tracker.record_update(
                session,
                previous,
                previous_before,
                actor=access.actor,
                action=AuditAction.DOCUMENT_UPDATED,
                operation=ChangeOperation.STATUS_CHANGE,
                dossier_uid=dossier.uid,
                reason=f"superseded by {record.uid}",
            )

        self._tracker.record_create(
            session,
            record,
            actor=access.actor,
            action=AuditAction.DOCUMENT_ADDED,
            dossier_uid=dossier.uid,
            detail={
                "document_class": record.document_class,
                "confidentiality": record.confidentiality,
                "content_hash": content_hash,
            },
        )
        self._touch_retention(session, dossier)
        return record

    def list_documents(
        self,
        session: Session,
        access: AuthorizedAccess,
        *,
        include_superseded: bool = False,
    ) -> list[DossierDocument]:
        """Return the documents the caller's access level reaches.

        Filtering happens in the query, not after: a document above the
        caller's ceiling must not be loaded, counted or hinted at.
        """
        reachable = [
            level.value
            for level in Confidentiality
            if level.is_reachable_from(access.max_level)
        ]
        stmt = select(DossierDocument).where(
            DossierDocument.dossier_uid == access.dossier_uid,
            DossierDocument.confidentiality.in_(reachable),
        )
        if not include_superseded:
            stmt = stmt.where(DossierDocument.status == DocumentStatus.CURRENT.value)
        documents = list(
            session.execute(stmt.order_by(DossierDocument.created_at.desc())).scalars()
        )
        self._ledger.append(
            session,
            actor=access.actor,
            action=AuditAction.DOSSIER_READ,
            resource_type="dossier",
            resource_uid=access.dossier_uid,
            dossier_uid=access.dossier_uid,
            detail={
                "returned": len(documents),
                "max_level": access.max_level.value,
            },
        )
        return documents

    def read_document(
        self, session: Session, access: AuthorizedAccess, document_uid: str
    ) -> DossierDocument:
        document = session.get(DossierDocument, document_uid)
        if document is None or document.dossier_uid != access.dossier_uid:
            raise DossierError("unknown document")
        level = Confidentiality(document.confidentiality)
        if not level.is_reachable_from(access.max_level):
            # Same error as "not found": distinguishing the two would leak the
            # existence of restricted material.
            self._ledger.append(
                session,
                actor=access.actor,
                action=AuditAction.ACCESS_DENIED,
                resource_type="dossier_document",
                resource_uid=document_uid,
                dossier_uid=access.dossier_uid,
                detail={"reason": "confidentiality level exceeds grant"},
            )
            raise DossierError("unknown document")
        self._ledger.append(
            session,
            actor=access.actor,
            action=AuditAction.DOCUMENT_READ,
            resource_type="dossier_document",
            resource_uid=document_uid,
            dossier_uid=access.dossier_uid,
            detail={"confidentiality": document.confidentiality},
        )
        return document

    def retract_document(
        self,
        session: Session,
        access: AuthorizedAccess,
        document_uid: str,
        *,
        reason: str,
    ) -> DossierDocument:
        """Mark a document as recorded in error.

        Clinical records are corrected by superseding, never by deletion: a
        later reader has to be able to see that a wrong result existed and was
        withdrawn.
        """
        document = self.read_document(session, access, document_uid)
        before = snapshot(document)
        document.status = DocumentStatus.RETRACTED.value
        self._tracker.record_update(
            session,
            document,
            before,
            actor=access.actor,
            action=AuditAction.DOCUMENT_RETRACTED,
            operation=ChangeOperation.STATUS_CHANGE,
            dossier_uid=access.dossier_uid,
            reason=reason,
        )
        return document

    def _touch_retention(self, session: Session, dossier: Dossier) -> None:
        """Retention runs from the *last* entry, so every write pushes it out."""
        dossier.retention_until = self._retention_horizon(utcnow())
        session.flush()
