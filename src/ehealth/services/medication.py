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
from datetime import date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import (
    IdentifierError,
    Uid,
    is_valid_atc,
    is_valid_gln,
    is_valid_gtin,
    is_valid_pharmacode,
    new_uid,
    normalise_swissmedic_authorisation,
)
from ehealth.models.audit import AuditAction, ChangeOperation
from ehealth.models.base import Confidentiality
from ehealth.models.clinical import (
    AuthorisationStatus,
    DispensingCategory,
    MedicationEventKind,
    MedicationStatement,
    MedicationStatus,
    MedicinalProduct,
    NarcoticSchedule,
)
from ehealth.models.core import PersonRoleKind
from ehealth.services.access import AuthorizedAccess
from ehealth.services.audit import ActorContext, AuditLedger
from ehealth.services.changelog import ChangeTracker, snapshot

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ehealth.models.core import ProfessionalCredential
    from ehealth.services.persons import PersonService


class MedicationError(Exception):
    pass


@dataclass(slots=True)
class ProductInput:
    gtin: str
    name: str
    swissmedic_authorisation: str | None = None
    pharmacode: str | None = None
    active_ingredient: str | None = None
    atc_code: str | None = None
    dose_form: str | None = None
    strength: str | None = None
    package_size: str | None = None
    marketing_authorisation_holder: str | None = None
    marketing_authorisation_holder_gln: str | None = None
    dispensing_category: DispensingCategory = DispensingCategory.B
    narcotic_schedule: NarcoticSchedule = NarcoticSchedule.NONE
    authorisation_status: AuthorisationStatus = AuthorisationStatus.AUTHORISED
    authorisation_valid_until: date | None = None
    sl_listed: bool = False
    sl_number: str | None = None


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
        if self.by_gtin(session, product.gtin) is not None:
            raise MedicationError("a product with this GTIN is already registered")

        # Every Swiss identifier is validated at the boundary, so a malformed
        # authorisation number cannot reach a prescription.
        authorisation = None
        if product.swissmedic_authorisation:
            try:
                authorisation = normalise_swissmedic_authorisation(
                    product.swissmedic_authorisation
                )
            except IdentifierError as exc:
                raise MedicationError(str(exc)) from exc
        if product.atc_code and not is_valid_atc(product.atc_code):
            raise MedicationError("ATC code is malformed")
        if product.pharmacode:
            if not is_valid_pharmacode(product.pharmacode):
                raise MedicationError("Pharmacode is malformed")
            if self.by_pharmacode(session, product.pharmacode) is not None:
                raise MedicationError(
                    "a product with this Pharmacode is already registered"
                )
        if product.marketing_authorisation_holder_gln and not is_valid_gln(
            product.marketing_authorisation_holder_gln
        ):
            raise MedicationError("authorisation holder GLN check digit is wrong")

        record = MedicinalProduct(
            uid=new_uid("med"),
            gtin=product.gtin,
            name=product.name,
            swissmedic_authorisation=authorisation,
            authorisation_status=product.authorisation_status.value,
            authorisation_valid_until=product.authorisation_valid_until,
            pharmacode=product.pharmacode.lstrip("0") if product.pharmacode else None,
            active_ingredient=product.active_ingredient,
            atc_code=product.atc_code.upper() if product.atc_code else None,
            dose_form=product.dose_form,
            strength=product.strength,
            package_size=product.package_size,
            marketing_authorisation_holder=product.marketing_authorisation_holder,
            marketing_authorisation_holder_gln=product.marketing_authorisation_holder_gln,
            dispensing_category=product.dispensing_category.value,
            narcotic_schedule=product.narcotic_schedule.value,
            sl_listed=product.sl_listed,
            sl_number=product.sl_number,
        )
        session.add(record)
        session.flush()
        self._tracker.record_create(
            session,
            record,
            actor=actor,
            action=AuditAction.PRODUCT_REGISTERED,
            detail={
                "gtin": product.gtin,
                "swissmedic_authorisation": authorisation,
                "atc": record.atc_code,
                "dispensing_category": record.dispensing_category,
                "narcotic_schedule": record.narcotic_schedule,
            },
        )
        return record

    @staticmethod
    def by_pharmacode(session: Session, pharmacode: str) -> MedicinalProduct | None:
        return (
            session.execute(
                select(MedicinalProduct).where(
                    MedicinalProduct.pharmacode == pharmacode.lstrip("0")
                )
            )
            .scalars()
            .first()
        )

    @staticmethod
    def by_swissmedic_authorisation(
        session: Session, number: str
    ) -> list[MedicinalProduct]:
        """All packages under one authorisation number."""
        base = normalise_swissmedic_authorisation(number).split("-")[0]
        return list(
            session.execute(
                select(MedicinalProduct).where(
                    MedicinalProduct.swissmedic_authorisation.startswith(base)
                )
            ).scalars()
        )

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


#: Which event kinds require a licensed professional behind them.
#:
#: A patient may record their own self-medication, and that is the point of the
#: ``SELF_REPORTED`` kind — a complete medication list is worth more than a
#: tidy one. Prescribing and dispensing are different: HMG art. 24 ff. ties
#: them to a profession and a licence, so the system does too.
CLINICALLY_AUTHORED_KINDS = frozenset(
    {
        MedicationEventKind.PRESCRIPTION,
        MedicationEventKind.DISPENSE,
        MedicationEventKind.ADMINISTRATION,
    }
)


class MedicationService:
    """Patient-specific medication events."""

    def __init__(
        self,
        ledger: AuditLedger,
        tracker: ChangeTracker,
        persons: "PersonService | None" = None,
    ) -> None:
        self._ledger = ledger
        self._tracker = tracker
        # Injected rather than imported at call time so the authority check is
        # visible in the constructor and can be exercised in isolation.
        self._persons = persons

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
            if not product.is_marketable(utcnow().date()):
                raise MedicationError(
                    "product is not authorised for the Swiss market"
                )

        credential = self._check_authority(
            session, statement, product, recorded_by_uid=recorded_by_uid
        )

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
            organization_uid=organization_uid or (
                credential.organization_uid if credential else None
            ),
            recorded_under_credential_uid=credential.uid if credential else None,
            recorded_by_gln=credential.gln if credential else None,
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
                # Narcotics get their own flag in the trail so a BetmG audit is
                # a query rather than a reconstruction.
                "narcotic_schedule": (
                    product.narcotic_schedule if product else None
                ),
                "dispensing_category": (
                    product.dispensing_category if product else None
                ),
                "prescriber_gln": record.recorded_by_gln,
                "credential_verified": bool(credential and credential.is_verified),
            },
        )
        return record

    def _check_authority(
        self,
        session: Session,
        statement: StatementInput,
        product: MedicinalProduct | None,
        *,
        recorded_by_uid: str,
    ) -> "ProfessionalCredential | None":
        """Refuse a clinical entry from someone who may not make it.

        The rule that matters: a prescription-only product (Swissmedic
        category A or B) may only be prescribed by a professional whose
        cantonal licence is live *now*. A lapsed or suspended licence stops
        prescribing at once, which is exactly what a licence is for.
        """
        if statement.kind not in CLINICALLY_AUTHORED_KINDS:
            return None
        if self._persons is None:
            # No registry wired in — the deployment has opted out of the
            # authority check, and that is a deliberate configuration rather
            # than a silent gap.
            return None

        from ehealth.services.persons import PersonError

        try:
            self._persons.require_role(
                session, recorded_by_uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
            )
        except PersonError as exc:
            raise MedicationError(
                "only a healthcare professional may record this entry"
            ) from exc

        credential = self._persons.active_credential(session, recorded_by_uid)
        if credential is None:
            raise MedicationError(
                "no professional credential with a live practice licence"
            )

        needs_prescriber = statement.kind is MedicationEventKind.PRESCRIPTION or (
            product is not None and product.requires_prescription
        )
        if needs_prescriber and not credential.may_prescribe(utcnow().date()):
            raise MedicationError(
                "this profession and licence do not carry prescribing authority"
            )
        return credential

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
