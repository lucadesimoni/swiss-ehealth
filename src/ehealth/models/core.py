# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Persons and institutions.

Every natural person in the system — patient, healthcare professional and
visitor alike — is one :class:`Person` row with one UID. Which role they can
act in is a property of the row, not of a separate table, so a physician who
is also a patient is one identity with one AHVN13-derived pseudonym rather
than two disconnected records.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from sqlalchemy import Boolean, Date, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import TimestampMixin, UidPk, VersionMixin


class PersonKind(StrEnum):
    PATIENT = "patient"
    HEALTHCARE_PROFESSIONAL = "healthcare_professional"
    VISITOR = "visitor"
    REPRESENTATIVE = "representative"


class IdentificationMethod(StrEnum):
    """How the person's identity was established.

    The AHVN13 is the norm. Cross-border patients and visitors who have no
    AHVN13 still need a UID, so the method is recorded explicitly and a
    non-AHVN13 identification is visible everywhere it matters rather than
    being indistinguishable from a verified one.
    """

    AHVN13 = "ahvn13"
    PASSPORT = "passport"
    RESIDENCE_PERMIT = "residence_permit"
    TEMPORARY = "temporary"


class PersonStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECEASED = "deceased"
    BLOCKED = "blocked"


class Organization(Base, TimestampMixin, VersionMixin, UidPk):
    """A healthcare institution, identified by its Swiss CHE UID."""

    __tablename__ = "organization"

    che_uid: Mapped[str | None] = mapped_column(String(9), unique=True)
    gln: Mapped[str | None] = mapped_column(String(13), unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, default="practice")
    #: Community (Gemeinschaft) the institution is affiliated with under EPDG.
    community: Mapped[str | None] = mapped_column(String(120))
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Person(Base, TimestampMixin, VersionMixin, UidPk):
    """A natural person.

    Direct identifiers (names, contact data, document numbers) are stored as
    AEAD envelopes bound to this row's UID; only the pseudonymous keys and the
    coarse attributes needed for matching and safety live in the clear.
    """

    __tablename__ = "person"
    __table_args__ = (
        UniqueConstraint("ppid", name="uq_person_ppid"),
        UniqueConstraint("spid", name="uq_person_spid"),
        Index("ix_person_lookup_index", "lookup_index"),
        Index("ix_person_kind_status", "kind", "status"),
    )

    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=PersonStatus.ACTIVE.value
    )
    identification_method: Mapped[str] = mapped_column(
        String(24), nullable=False, default=IdentificationMethod.AHVN13.value
    )

    #: 256 bit pseudonym derived from the AHVN13. NULL only when the person
    #: was identified by another method.
    ppid: Mapped[str | None] = mapped_column(String(64))
    #: 13 digit sector identifier (761.xxxx.xxxx.xx) for interop and display.
    spid: Mapped[str | None] = mapped_column(String(13))
    #: Rotatable blind index over the AHVN13, for "do we know this person".
    lookup_index: Mapped[str | None] = mapped_column(String(80))
    #: AEAD-sealed AHVN13; NULL in zero-retention deployments.
    sealed_ahvn: Mapped[str | None] = mapped_column(String(256))

    given_name_enc: Mapped[str | None] = mapped_column(String(512))
    family_name_enc: Mapped[str | None] = mapped_column(String(512))
    #: Kept in the clear: needed for dose calculation and identity matching,
    #: and useless on its own for re-identification at population scale.
    birth_date: Mapped[date | None] = mapped_column(Date)
    #: ISO 5218; relevant to reference ranges and dosing.
    administrative_sex: Mapped[str | None] = mapped_column(String(16))
    contact_email_enc: Mapped[str | None] = mapped_column(String(512))
    contact_phone_enc: Mapped[str | None] = mapped_column(String(512))
    #: Non-AHVN13 identification document, sealed the same way.
    id_document_enc: Mapped[str | None] = mapped_column(String(512))

    #: Healthcare professionals carry a GLN and belong to an institution.
    gln: Mapped[str | None] = mapped_column(String(13))
    profession: Mapped[str | None] = mapped_column(String(80))
    organization_uid: Mapped[str | None] = mapped_column(
        ForeignKey("organization.uid", ondelete="RESTRICT")
    )

    def is_patient(self) -> bool:
        return self.kind == PersonKind.PATIENT.value

    def is_professional(self) -> bool:
        return self.kind == PersonKind.HEALTHCARE_PROFESSIONAL.value
