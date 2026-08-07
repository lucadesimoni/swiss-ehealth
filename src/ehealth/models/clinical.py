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


class MedicinalProduct(Base, TimestampMixin, VersionMixin, UidPk):
    """A marketed medicinal product package.

    Keyed on the GTIN carried by the package barcode, cross-referenced to the
    Swissmedic authorisation number and the ATC code so the same substance can
    be recognised across brands and pack sizes.
    """

    __tablename__ = "medicinal_product"
    __table_args__ = (
        UniqueConstraint("gtin", name="uq_medicinal_product_gtin"),
        Index("ix_medicinal_product_atc", "atc_code"),
        Index("ix_medicinal_product_name", "name"),
    )

    gtin: Mapped[str] = mapped_column(String(14), nullable=False)
    swissmedic_authorisation: Mapped[str | None] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    active_ingredient: Mapped[str | None] = mapped_column(String(240))
    atc_code: Mapped[str | None] = mapped_column(String(12))
    dose_form: Mapped[str | None] = mapped_column(String(80))
    strength: Mapped[str | None] = mapped_column(String(80))
    package_size: Mapped[str | None] = mapped_column(String(60))
    marketing_authorisation_holder: Mapped[str | None] = mapped_column(String(200))
    #: Betäubungsmittel — extra audit scrutiny and stricter dispensing rules.
    narcotic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    prescription_only: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    withdrawn_at: Mapped[date | None] = mapped_column(Date)


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
    organization_uid: Mapped[str | None] = mapped_column(
        ForeignKey("organization.uid", ondelete="RESTRICT")
    )
    #: Links a dispense to the prescription it fulfils.
    based_on_uid: Mapped[str | None] = mapped_column(String(32))
