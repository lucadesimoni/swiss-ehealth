# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Dossiers, documents and the medication record."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    Date,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import (
    Confidentiality,
    JsonType,
    TimestampMixin,
    UidPk,
    UtcDateTime,
    VersionMixin,
)


class DossierStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"
    #: Retention period elapsed; content purged, shell kept for audit.
    ARCHIVED = "archived"


class Dossier(Base, TimestampMixin, VersionMixin, UidPk):
    """One patient's record. Participation in the EPD is voluntary, so a
    person may exist without a dossier."""

    __tablename__ = "dossier"
    __table_args__ = (UniqueConstraint("patient_uid", name="uq_dossier_patient_uid"),)

    patient_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DossierStatus.ACTIVE.value
    )
    opened_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    #: Computed from the last entry plus the configured retention period.
    retention_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    #: Level applied to new documents unless the author says otherwise.
    default_confidentiality: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidentiality.NORMAL.value
    )
    home_community: Mapped[str | None] = mapped_column(String(120))


class DocumentStatus(StrEnum):
    CURRENT = "current"
    SUPERSEDED = "superseded"
    #: Clinically withdrawn but retained — health records are never deleted
    #: for correctness, only marked.
    RETRACTED = "retracted"


class DossierDocument(Base, TimestampMixin, VersionMixin, UidPk):
    """A document in the dossier.

    The payload itself lives in object storage; this row holds the metadata
    plus the content hash, so tampering with the blob store is detectable
    without trusting it.
    """

    __tablename__ = "dossier_document"
    __table_args__ = (
        Index("ix_document_dossier_created", "dossier_uid", "created_at"),
        Index("ix_document_dossier_conf", "dossier_uid", "confidentiality"),
    )

    dossier_uid: Mapped[str] = mapped_column(
        ForeignKey("dossier.uid", ondelete="RESTRICT"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    #: SNOMED CT / DocumentEntry.classCode style coding.
    document_class: Mapped[str] = mapped_column(String(80), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(120), nullable=False)
    language: Mapped[str] = mapped_column(String(8), nullable=False, default="de-CH")
    confidentiality: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidentiality.NORMAL.value
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DocumentStatus.CURRENT.value
    )
    author_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    author_organization_uid: Mapped[str | None] = mapped_column(
        ForeignKey("organization.uid", ondelete="RESTRICT")
    )
    #: SHA-256 of the payload, hex encoded.
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    storage_ref: Mapped[str | None] = mapped_column(String(300))
    supersedes_uid: Mapped[str | None] = mapped_column(String(32))
    service_start: Mapped[datetime | None] = mapped_column(UtcDateTime)
    service_end: Mapped[datetime | None] = mapped_column(UtcDateTime)


# --------------------------------------------------------------------------
# Medication
# --------------------------------------------------------------------------


class DispensingCategory(StrEnum):
    """Swissmedic dispensing categories (Abgabekategorien) under HMG/AMBV.

    Category C was abolished in 2019 and its products reassigned to B or D; it
    is absent here on purpose, so legacy data carrying it fails loudly at the
    boundary instead of being silently accepted.
    """

    #: Verschärft rezeptpflichtig — single dispensing per prescription.
    A = "A"
    #: Rezeptpflichtig.
    B = "B"
    #: Abgabe nach Fachberatung, no prescription.
    D = "D"
    #: Freiverkäuflich.
    E = "E"

    @property
    def requires_prescription(self) -> bool:
        return self in (DispensingCategory.A, DispensingCategory.B)


class NarcoticSchedule(StrEnum):
    """BetmVV-EDI annexes. Narcotics carry stricter dispensing and audit."""

    NONE = "none"
    #: Verzeichnis a — controlled substances, full control.
    A = "a"
    #: Verzeichnis b — partially excepted.
    B = "b"
    #: Verzeichnis c — partially excepted, lower risk.
    C = "c"
    #: Verzeichnis d — prohibited substances.
    D = "d"

    @property
    def is_narcotic(self) -> bool:
        return self is not NarcoticSchedule.NONE


class AuthorisationStatus(StrEnum):
    """Swissmedic marketing authorisation state under HMG art. 9 ff."""

    AUTHORISED = "authorised"
    #: Befristete Bewilligung / Art. 9b temporary authorisation.
    TEMPORARY = "temporary"
    SUSPENDED = "suspended"
    #: Withdrawn or lapsed. Never prescribable, still readable in history.
    WITHDRAWN = "withdrawn"


class MedicinalProduct(Base, TimestampMixin, VersionMixin, UidPk):
    """A marketed medicinal product package, identified the way Swiss law does.

    Four identifiers, because Swiss practice uses four and they answer
    different questions:

    * **Swissmedic authorisation number** — is this product legally on the
      market at all (HMG art. 9)?
    * **GTIN** — which package is this, scanned off the box?
    * **Pharmacode** — Refdata's article number, what ordering and logistics
      systems speak.
    * **ATC** — what substance class is it, for interaction and duplicate
      checks across brands.

    The dispensing category and narcotic schedule are what actually gate
    prescribing, which is why they are enums rather than a single boolean.
    """

    __tablename__ = "medicinal_product"
    __table_args__ = (
        UniqueConstraint("gtin", name="uq_medicinal_product_gtin"),
        UniqueConstraint("pharmacode", name="uq_medicinal_product_pharmacode"),
        Index("ix_medicinal_product_atc", "atc_code"),
        Index("ix_medicinal_product_name", "name"),
        Index("ix_medicinal_product_authorisation", "swissmedic_authorisation"),
    )

    gtin: Mapped[str] = mapped_column(String(14), nullable=False)
    #: Five digits, optionally with a package suffix: ``62536`` / ``62536-001``.
    swissmedic_authorisation: Mapped[str | None] = mapped_column(String(12))
    authorisation_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AuthorisationStatus.AUTHORISED.value
    )
    authorisation_valid_until: Mapped[date | None] = mapped_column(Date)
    #: Refdata article number, up to seven digits.
    pharmacode: Mapped[str | None] = mapped_column(String(7))

    name: Mapped[str] = mapped_column(String(240), nullable=False)
    active_ingredient: Mapped[str | None] = mapped_column(String(240))
    atc_code: Mapped[str | None] = mapped_column(String(12))
    dose_form: Mapped[str | None] = mapped_column(String(80))
    strength: Mapped[str | None] = mapped_column(String(80))
    package_size: Mapped[str | None] = mapped_column(String(60))
    marketing_authorisation_holder: Mapped[str | None] = mapped_column(String(200))
    #: GLN of the authorisation holder, so the responsible company is
    #: identifiable rather than merely named.
    marketing_authorisation_holder_gln: Mapped[str | None] = mapped_column(String(13))

    dispensing_category: Mapped[str] = mapped_column(
        String(2), nullable=False, default=DispensingCategory.B.value
    )
    narcotic_schedule: Mapped[str] = mapped_column(
        String(8), nullable=False, default=NarcoticSchedule.NONE.value
    )

    #: Spezialitätenliste (KVG art. 52) — whether compulsory health insurance
    #: reimburses it, and under which entry.
    sl_listed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sl_number: Mapped[str | None] = mapped_column(String(20))

    withdrawn_at: Mapped[date | None] = mapped_column(Date)

    @property
    def requires_prescription(self) -> bool:
        return DispensingCategory(self.dispensing_category).requires_prescription

    @property
    def is_narcotic(self) -> bool:
        return NarcoticSchedule(self.narcotic_schedule).is_narcotic

    def is_marketable(self, on: date) -> bool:
        """Whether the product may still be prescribed or dispensed on ``on``."""
        if self.authorisation_status not in (
            AuthorisationStatus.AUTHORISED.value,
            AuthorisationStatus.TEMPORARY.value,
        ):
            return False
        if self.withdrawn_at is not None and on >= self.withdrawn_at:
            return False
        return (
            self.authorisation_valid_until is None
            or on <= self.authorisation_valid_until
        )


class MedicationEventKind(StrEnum):
    PRESCRIPTION = "prescription"
    DISPENSE = "dispense"
    ADMINISTRATION = "administration"
    SELF_REPORTED = "self_reported"
    STOPPED = "stopped"


class MedicationStatus(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    STOPPED = "stopped"
    #: Recorded in error — kept, never deleted, and excluded from the
    #: reconciled list.
    ENTERED_IN_ERROR = "entered_in_error"


class MedicationStatement(Base, TimestampMixin, VersionMixin, UidPk):
    """One medication event in a patient's record.

    Prescription, dispense and administration are the same shape and differ by
    ``kind``, which keeps the reconciled medication list a single ordered
    query rather than a three-way merge.
    """

    __tablename__ = "medication_statement"
    __table_args__ = (
        Index("ix_medstatement_dossier_kind", "dossier_uid", "kind"),
        Index("ix_medstatement_dossier_effective", "dossier_uid", "effective_start"),
        UniqueConstraint(
            "dossier_uid", "offline_client_uid", name="uq_medstatement_offline_uid"
        ),
    )

    dossier_uid: Mapped[str] = mapped_column(
        ForeignKey("dossier.uid", ondelete="RESTRICT"), nullable=False
    )
    product_uid: Mapped[str | None] = mapped_column(
        ForeignKey("medicinal_product.uid", ondelete="RESTRICT")
    )
    #: Free-text fallback for products with no GTIN (magistral formulas,
    #: foreign packages). Exactly one of product_uid/product_text is set.
    product_text: Mapped[str | None] = mapped_column(String(240))
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=MedicationStatus.ACTIVE.value
    )
    confidentiality: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidentiality.NORMAL.value
    )
    #: Structured dosage: {"amount": 1, "unit": "tablet", "frequency": "1-0-1-0",
    #: "route": "oral", "as_needed": false}
    dosage: Mapped[dict] = mapped_column(JsonType, nullable=False, default=dict)
    quantity: Mapped[str | None] = mapped_column(String(60))
    reason: Mapped[str | None] = mapped_column(Text)
    effective_start: Mapped[datetime | None] = mapped_column(UtcDateTime)
    effective_end: Mapped[datetime | None] = mapped_column(UtcDateTime)
    recorded_by_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    #: The credential under which this was prescribed or dispensed, and the
    #: GLN copied from it. Copied rather than joined on purpose: a
    #: prescription must stay attributable to the licence that was live when it
    #: was written, even after that credential later lapses or is corrected.
    recorded_under_credential_uid: Mapped[str | None] = mapped_column(String(32))
    recorded_by_gln: Mapped[str | None] = mapped_column(String(13))
    organization_uid: Mapped[str | None] = mapped_column(
        ForeignKey("organization.uid", ondelete="RESTRICT")
    )
    #: Links a dispense to the prescription it fulfils.
    based_on_uid: Mapped[str | None] = mapped_column(String(32))

    #: Set when the entry was captured on a patient's device without
    #: connectivity. The client generates the id offline (a ULID, so it needs
    #: no coordination) and it is the idempotency key: replaying a sync that
    #: half-succeeded returns the same row instead of duplicating the entry.
    offline_client_uid: Mapped[str | None] = mapped_column(String(64))
    #: The client's clock at capture. Recorded because it is clinically
    #: meaningful — "I took it at 08:00" — and **never** used for ordering,
    #: because a device clock is not evidence. ``created_at`` stays
    #: authoritative.
    captured_offline_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
