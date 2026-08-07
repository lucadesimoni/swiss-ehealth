# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The medication record.

Prescriptions, dispenses, administrations and patient-reported medication are
one table differing by ``kind``, which makes the reconciled list — the thing a
clinician actually needs — a single ordered query rather than a merge of three
sources that can disagree.

Every statement is versioned and audited like any other record, and a
statement is never deleted: stopping a medication is a status change, and a
mistaken entry becomes ``entered_in_error`` while staying visible in the
history.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import Uid, is_valid_gtin, new_uid
from ehealth.models.audit import AuditAction, ChangeOperation
from ehealth.models.base import Confidentiality
from ehealth.models.clinical import (
    MedicationEventKind,
    MedicationStatement,
    MedicationStatus,
    MedicinalProduct,
)
from ehealth.services.access import AuthorizedAccess
from ehealth.services.audit import ActorContext, AuditLedger
from ehealth.services.changelog import ChangeTracker, snapshot


class MedicationError(Exception):
    pass


@dataclass(slots=True)
class ProductInput:
    gtin: str
    name: str
    swissmedic_authorisation: str | None = None
    active_ingredient: str | None = None
    atc_code: str | None = None
    dose_form: str | None = None
    strength: str | None = None
    package_size: str | None = None
    marketing_authorisation_holder: str | None = None
    narcotic: bool = False
    prescription_only: bool = True


@dataclass(slots=True)
class StatementInput:
    kind: MedicationEventKind
    product_uid: str | None = None
    product_text: str | None = None
    dosage: dict = field(default_factory=dict)
    quantity: str | None = None
    reason: str | None = None
    effective_start: datetime | None = None
    effective_end: datetime | None = None
    confidentiality: Confidentiality = Confidentiality.NORMAL
    based_on_uid: str | None = None


class MedicationCatalogue:
    """The product master data. Shared across dossiers, not patient data."""

    def __init__(self, ledger: AuditLedger, tracker: ChangeTracker) -> None:
        self._ledger = ledger
        self._tracker = tracker

    def register(
        self, session: Session, actor: ActorContext, product: ProductInput
    ) -> MedicinalProduct:
        if not is_valid_gtin(product.gtin):
            raise MedicationError("GTIN check digit is wrong")
        existing = self.by_gtin(session, product.gtin)
        if existing is not None:
            raise MedicationError("a product with this GTIN is already registered")
        record = MedicinalProduct(
            uid=new_uid("med"),
            gtin=product.gtin,
            name=product.name,
            swissmedic_authorisation=product.swissmedic_authorisation,
            active_ingredient=product.active_ingredient,
            atc_code=product.atc_code,
            dose_form=product.dose_form,
            strength=product.strength,
            package_size=product.package_size,
            marketing_authorisation_holder=product.marketing_authorisation_holder,
            narcotic=product.narcotic,
            prescription_only=product.prescription_only,
        )
        session.add(record)
        session.flush()
        self._tracker.record_create(
            session,
            record,
            actor=actor,
            action=AuditAction.PRODUCT_REGISTERED,
            detail={"gtin": product.gtin, "atc": product.atc_code},
        )
        return record

    @staticmethod
    def by_gtin(session: Session, gtin: str) -> MedicinalProduct | None:
        return (
            session.execute(
                select(MedicinalProduct).where(MedicinalProduct.gtin == gtin)
            )
            .scalars()
            .first()
        )

    @staticmethod
    def search(
        session: Session, term: str, *, limit: int = 25
    ) -> list[MedicinalProduct]:
        pattern = f"%{term.strip()}%"
        return list(
            session.execute(
                select(MedicinalProduct)
                .where(
                    or_(
                        MedicinalProduct.name.ilike(pattern),
                        MedicinalProduct.active_ingredient.ilike(pattern),
                        MedicinalProduct.atc_code.ilike(pattern),
                        MedicinalProduct.gtin == term.strip(),
                    )
                )
                .order_by(MedicinalProduct.name)
                .limit(min(limit, 100))
            ).scalars()
        )


class MedicationService:
    """Patient-specific medication events."""

    def __init__(self, ledger: AuditLedger, tracker: ChangeTracker) -> None:
        self._ledger = ledger
        self._tracker = tracker

    def record(
        self,
        session: Session,
        access: AuthorizedAccess,
        statement: StatementInput,
        *,
        recorded_by_uid: str,
        organization_uid: str | None = None,
    ) -> MedicationStatement:
        if bool(statement.product_uid) == bool(statement.product_text):
            raise MedicationError(
                "give either a catalogue product or free text, not both or neither"
            )
        product = None
        if statement.product_uid:
            Uid.parse_typed(statement.product_uid, "med")
            product = session.get(MedicinalProduct, statement.product_uid)
            if product is None:
                raise MedicationError("unknown product")

        if statement.based_on_uid:
            prescription = session.get(MedicationStatement, statement.based_on_uid)
            if prescription is None or prescription.dossier_uid != access.dossier_uid:
                raise MedicationError("prescription does not belong to this dossier")
            if prescription.kind != MedicationEventKind.PRESCRIPTION.value:
                raise MedicationError("based_on must reference a prescription")

        record = MedicationStatement(
            uid=new_uid("mst"),
            dossier_uid=access.dossier_uid,
            product_uid=statement.product_uid,
            product_text=statement.product_text,
            kind=statement.kind.value,
            status=MedicationStatus.ACTIVE.value,
            confidentiality=statement.confidentiality.value,
            dosage=statement.dosage or {},
            quantity=statement.quantity,
            reason=statement.reason,
            effective_start=statement.effective_start or utcnow(),
            effective_end=statement.effective_end,
            recorded_by_uid=recorded_by_uid,
            organization_uid=organization_uid,
            based_on_uid=statement.based_on_uid,
        )
        session.add(record)
        session.flush()
        self._tracker.record_create(
            session,
            record,
            actor=access.actor,
            action=AuditAction.MEDICATION_ADDED,
            dossier_uid=access.dossier_uid,
            detail={
                "kind": record.kind,
                "product_uid": record.product_uid,
                "narcotic": bool(product and product.narcotic),
            },
        )
        return record

    def list_for_dossier(
        self,
        session: Session,
        access: AuthorizedAccess,
        *,
        kinds: list[MedicationEventKind] | None = None,
        active_only: bool = False,
    ) -> list[MedicationStatement]:
        reachable = [
            level.value
            for level in Confidentiality
            if level.is_reachable_from(access.max_level)
        ]
        stmt = select(MedicationStatement).where(
            MedicationStatement.dossier_uid == access.dossier_uid,
            MedicationStatement.confidentiality.in_(reachable),
        )
        if kinds:
            stmt = stmt.where(MedicationStatement.kind.in_([k.value for k in kinds]))
        if active_only:
            stmt = stmt.where(
                MedicationStatement.status == MedicationStatus.ACTIVE.value
            )
        rows = list(
            session.execute(
                stmt.order_by(MedicationStatement.effective_start.desc())
            ).scalars()
        )
        self._ledger.append(
            session,
            actor=access.actor,
            action=AuditAction.MEDICATION_READ,
            resource_type="medication_statement",
            dossier_uid=access.dossier_uid,
            detail={"returned": len(rows), "max_level": access.max_level.value},
        )
        return rows

    def reconciled_list(
        self, session: Session, access: AuthorizedAccess
    ) -> list[MedicationStatement]:
        """The current medication list.

        "Current" means: active, not entered in error, and not ended in the
        past. Prescriptions that a dispense already superseded are dropped in
        favour of the dispense, because what the patient actually has is what
        matters at the point of care.
        """
        rows = self.list_for_dossier(session, access, active_only=True)
        now = utcnow()
        superseded = {r.based_on_uid for r in rows if r.based_on_uid}
        return [
            row
            for row in rows
            if row.uid not in superseded
            and row.status != MedicationStatus.ENTERED_IN_ERROR.value
            and (row.effective_end is None or row.effective_end > now)
        ]

    def stop(
        self,
        session: Session,
        access: AuthorizedAccess,
        statement_uid: str,
        *,
        reason: str,
        effective_end: datetime | None = None,
    ) -> MedicationStatement:
        record = self._get_in_scope(session, access, statement_uid)
        before = snapshot(record)
        record.status = MedicationStatus.STOPPED.value
        record.effective_end = effective_end or utcnow()
        self._tracker.record_update(
            session,
            record,
            before,
            actor=access.actor,
            action=AuditAction.MEDICATION_STOPPED,
            operation=ChangeOperation.STATUS_CHANGE,
            dossier_uid=access.dossier_uid,
            reason=reason,
        )
        return record

    def mark_entered_in_error(
        self,
        session: Session,
        access: AuthorizedAccess,
        statement_uid: str,
        *,
        reason: str,
    ) -> MedicationStatement:
        record = self._get_in_scope(session, access, statement_uid)
        before = snapshot(record)
        record.status = MedicationStatus.ENTERED_IN_ERROR.value
        self._tracker.record_update(
            session,
            record,
            before,
            actor=access.actor,
            action=AuditAction.MEDICATION_UPDATED,
            operation=ChangeOperation.STATUS_CHANGE,
            dossier_uid=access.dossier_uid,
            reason=reason,
        )
        return record

    def update_dosage(
        self,
        session: Session,
        access: AuthorizedAccess,
        statement_uid: str,
        *,
        dosage: dict,
        reason: str,
    ) -> MedicationStatement:
        record = self._get_in_scope(session, access, statement_uid)
        before = snapshot(record)
        record.dosage = dosage
        self._tracker.record_update(
            session,
            record,
            before,
            actor=access.actor,
            action=AuditAction.MEDICATION_UPDATED,
            dossier_uid=access.dossier_uid,
            reason=reason,
        )
        return record

    @staticmethod
    def _get_in_scope(
        session: Session, access: AuthorizedAccess, statement_uid: str
    ) -> MedicationStatement:
        record = session.get(MedicationStatement, statement_uid)
        if record is None or record.dossier_uid != access.dossier_uid:
            raise MedicationError("unknown medication statement")
        if not Confidentiality(record.confidentiality).is_reachable_from(
            access.max_level
        ):
            raise MedicationError("unknown medication statement")
        return record
