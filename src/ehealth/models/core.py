# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Persons, their roles, their professional credentials, and institutions.

One natural person is one :class:`Person` row with one ``per_`` UID, and the
roles they may act in are rows in :class:`PersonRole`. This matters more than
it looks: a physician is also somebody's patient, a nurse visits their own
parent in hospital, a paediatrician is the legal representative of their child.
Modelling the role as a column on the person would force those people into two
disconnected records with two different pseudonyms — and a patient whose own
doctor cannot see their record because the system split them in half is not an
edge case, it is Tuesday.

Because a role can be held, suspended and re-granted, each assignment carries
its own validity window and audit trail. Authority is therefore always a
question asked of the database at the moment it matters, never something baked
into an identifier.

Professional authority specifically lives in :class:`ProfessionalCredential`,
which records what Swiss law actually recognises: the GLN, the federal register
the professional appears in, and the cantonal licence to practise.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    Date,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import (
    JsonType,
    TimestampMixin,
    UidPk,
    UtcDateTime,
    VersionMixin,
)


class PersonRoleKind(StrEnum):
    """What a person may act as. A person may hold several at once."""

    PATIENT = "patient"
    HEALTHCARE_PROFESSIONAL = "healthcare_professional"
    VISITOR = "visitor"
    REPRESENTATIVE = "representative"


class RoleStatus(StrEnum):
    ACTIVE = "active"
    #: Temporarily withdrawn — a suspended practice licence, a visitor whose
    #: stay ended. The row stays so the history is legible.
    SUSPENDED = "suspended"
    REVOKED = "revoked"


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


class ProfessionalRegister(StrEnum):
    """The federal registers that establish a healthcare profession.

    Which register a professional appears in determines what they are legally
    allowed to do, so it is recorded rather than inferred from a job title.
    """

    #: Universitäre Medizinalberufe — physicians, dentists, chiropractors,
    #: pharmacists, veterinarians (MedBG art. 51 ff.).
    MEDREG = "medreg"
    #: Gesundheitsberufe — nursing, physiotherapy, midwifery and others
    #: (GesBG art. 24 ff.).
    NAREG = "nareg"
    #: Psychology professions (PsyG art. 40 ff.).
    PSYREG = "psyreg"
    #: Recognised by the institution but not in a federal register — medical
    #: assistants, administrative staff. Never granted prescribing authority.
    INSTITUTIONAL = "institutional"


class MedicalProfession(StrEnum):
    """MedBG art. 2 professions, plus the broader groups that also treat.

    Prescribing authority follows from this together with a valid licence,
    which is why the two are separate columns rather than one boolean.
    """

    PHYSICIAN = "physician"
    DENTIST = "dentist"
    CHIROPRACTOR = "chiropractor"
    PHARMACIST = "pharmacist"
    VETERINARIAN = "veterinarian"
    NURSE = "nurse"
    MIDWIFE = "midwife"
    PHYSIOTHERAPIST = "physiotherapist"
    PSYCHOTHERAPIST = "psychotherapist"
    OTHER = "other"


#: Professions that may prescribe medicinal products in Switzerland under HMG
#: art. 24 ff., subject to holding a valid cantonal licence. Pharmacists appear
#: because they may dispense category B products under the conditions of
#: HMG art. 24(1)(a) — the *authority* is here, the *limits* are enforced in
#: :mod:`ehealth.services.medication`.
PRESCRIBING_PROFESSIONS = frozenset(
    {
        MedicalProfession.PHYSICIAN,
        MedicalProfession.DENTIST,
        MedicalProfession.CHIROPRACTOR,
        MedicalProfession.VETERINARIAN,
        MedicalProfession.PHARMACIST,
    }
)

#: The 26 cantons. A practice licence (Berufsausübungsbewilligung) is issued
#: cantonally, so "which canton" is part of the credential, not decoration.
CANTONS = frozenset(
    "AG AI AR BE BL BS FR GE GL GR JU LU NE NW OW SG SH SO SZ TG TI UR VD VS ZG ZH".split()
)


class Organization(Base, TimestampMixin, VersionMixin, UidPk):
    """A healthcare institution, identified by its Swiss CHE UID and GLN."""

    __tablename__ = "organization"

    che_uid: Mapped[str | None] = mapped_column(String(9), unique=True)
    gln: Mapped[str | None] = mapped_column(String(13), unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False, default="practice")
    #: Community (Gemeinschaft/Stammgemeinschaft) under EPDG art. 11 — only a
    #: certified community may operate an EPD, so the affiliation is recorded.
    community: Mapped[str | None] = mapped_column(String(120))
    #: ZSR/RCC billing number of the institution, where it holds one.
    zsr_number: Mapped[str | None] = mapped_column(String(7))
    canton: Mapped[str | None] = mapped_column(String(2))
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
        Index("ix_person_status", "status"),
    )

    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=PersonStatus.ACTIVE.value
    )
    identification_method: Mapped[str] = mapped_column(
        String(24), nullable=False, default=IdentificationMethod.AHVN13.value
    )

    #: 256 bit pseudonym derived from the AHVN13. NULL only when the person
    #: was identified by another method.
    ppid: Mapped[str | None] = mapped_column(String(64))
    #: The 18 digit EPR-SPID (761…), the patient identifier of the electronic
    #: patient record. Eighteen digits, not thirteen — it is *derived from* the
    #: AHVN13 but is a different identifier with a different length.
    spid: Mapped[str | None] = mapped_column(String(18))
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
    #: Health insurance card number (VeKa, 20 digits) — a direct identifier,
    #: so sealed like the rest.
    veka_number_enc: Mapped[str | None] = mapped_column(String(512))


class PersonRole(Base, TimestampMixin, VersionMixin, UidPk):
    """One role a person holds, with its own validity and audit trail.

    A person may hold several simultaneously. Asking "may this person act as a
    professional right now" is therefore a query, and the answer can change
    without touching the person row or their identifiers.
    """

    __tablename__ = "person_role"
    __table_args__ = (
        UniqueConstraint("person_uid", "role", name="uq_person_role"),
        Index("ix_person_role_lookup", "person_uid", "role", "status"),
    )

    person_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=RoleStatus.ACTIVE.value
    )
    valid_from: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    granted_by_uid: Mapped[str | None] = mapped_column(String(32))
    note: Mapped[str | None] = mapped_column(Text)

    def is_live(self, now: datetime) -> bool:
        if self.status != RoleStatus.ACTIVE.value:
            return False
        if now < self.valid_from:
            return False
        return self.valid_until is None or now < self.valid_until


class ProfessionalCredential(Base, TimestampMixin, VersionMixin, UidPk):
    """What makes someone a healthcare professional in Swiss law.

    Three things have to line up before a person may treat and prescribe, and
    they are separate because they fail separately:

    * a **GLN** — the identifier Refdata assigns and that MedReg/NAREG/PsyReg,
      the EPD and e-prescriptions all key on;
    * an entry in a **federal register** for the profession;
    * a **cantonal licence to practise** (Berufsausübungsbewilligung), which
      is what actually expires, gets suspended, and is limited to a canton.

    The ZSR/RCC billing number is recorded alongside but is deliberately not
    part of the authority test: it says who may invoice an insurer, not who may
    treat a patient.
    """

    __tablename__ = "professional_credential"
    __table_args__ = (
        UniqueConstraint("gln", name="uq_credential_gln"),
        Index("ix_credential_person", "person_uid"),
        Index("ix_credential_register", "register", "profession"),
    )

    person_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    #: GTIN-13 with the same check digit. The professional's primary handle.
    gln: Mapped[str] = mapped_column(String(13), nullable=False)
    register: Mapped[str] = mapped_column(String(24), nullable=False)
    profession: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Weiterbildungstitel, e.g. "Facharzt Allgemeine Innere Medizin".
    specialisation: Mapped[str | None] = mapped_column(String(160))

    #: Cantonal practice licence. Without a live one, the credential grants no
    #: clinical authority however good the register entry looks.
    licence_canton: Mapped[str | None] = mapped_column(String(2))
    licence_number: Mapped[str | None] = mapped_column(String(64))
    licence_valid_from: Mapped[date | None] = mapped_column(Date)
    licence_valid_until: Mapped[date | None] = mapped_column(Date)
    licence_suspended: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    #: Billing number (SASIS). Invoicing authority, not clinical authority.
    zsr_number: Mapped[str | None] = mapped_column(String(7))
    organization_uid: Mapped[str | None] = mapped_column(
        ForeignKey("organization.uid", ondelete="RESTRICT")
    )

    #: When the GLN and register entry were last checked against the source of
    #: truth, and against which. An unverified credential is accepted but is
    #: visibly unverified everywhere it matters — "we were told" and "we
    #: checked" must never look the same in a health record.
    verified_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    verification_source: Mapped[str | None] = mapped_column(String(80))
    verification_evidence: Mapped[dict] = mapped_column(
        JsonType, nullable=False, default=dict
    )

    def licence_is_live(self, on: date) -> bool:
        """Whether the cantonal licence is in force on ``on``."""
        if self.licence_suspended:
            return False
        if self.licence_canton is None:
            return False
        if self.licence_valid_from is not None and on < self.licence_valid_from:
            return False
        return self.licence_valid_until is None or on <= self.licence_valid_until

    @property
    def is_verified(self) -> bool:
        return self.verified_at is not None

    def may_prescribe(self, on: date) -> bool:
        try:
            profession = MedicalProfession(self.profession)
        except ValueError:
            return False
        if profession not in PRESCRIBING_PROFESSIONS:
            return False
        if ProfessionalRegister(self.register) is ProfessionalRegister.INSTITUTIONAL:
            # Not in a federal register, so no prescribing authority, whatever
            # the job title says.
            return False
        return self.licence_is_live(on)
