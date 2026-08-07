# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Registering and resolving persons.

Every natural person the system touches — patient, professional, visitor —
gets a UID here, and where an AHVN13 exists it is turned into pseudonyms and
then dropped. There is no code path that writes an AHVN13 into a queryable
column.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ehealth.domain.identity import MAX_SPID_ATTEMPTS, IdentityService
from ehealth.domain.uid import Ahvn13, CheUid, IdentifierError, Uid, new_uid
from ehealth.models.audit import AuditAction
from ehealth.models.core import (
    IdentificationMethod,
    Organization,
    Person,
    PersonKind,
    PersonStatus,
)
from ehealth.services.audit import ActorContext, AuditLedger
from ehealth.services.changelog import ChangeTracker, snapshot


class PersonError(Exception):
    """Domain-level failure that is safe to surface to the caller."""


class DuplicatePersonError(PersonError):
    def __init__(self, existing_uid: str) -> None:
        super().__init__("a person with this AHV number is already registered")
        self.existing_uid = existing_uid


@dataclass(slots=True)
class PersonRegistration:
    """Input for registering a person.

    ``ahvn13`` is optional only because cross-border patients and walk-in
    visitors exist; when it is absent, ``identification_method`` must say what
    was used instead, and that shows up on every downstream record.
    """

    kind: PersonKind
    given_name: str
    family_name: str
    ahvn13: str | None = None
    birth_date: date | None = None
    administrative_sex: str | None = None
    email: str | None = None
    phone: str | None = None
    identification_method: IdentificationMethod = IdentificationMethod.AHVN13
    id_document: str | None = None
    gln: str | None = None
    profession: str | None = None
    organization_uid: str | None = None


@dataclass(frozen=True, slots=True)
class PersonView:
    """Decrypted, presentable form of a person. Built only for callers that
    have passed an access check."""

    uid: str
    kind: str
    status: str
    spid: str | None
    given_name: str | None
    family_name: str | None
    birth_date: date | None
    administrative_sex: str | None
    email: str | None
    phone: str | None
    gln: str | None
    profession: str | None
    organization_uid: str | None
    identification_method: str
    version: int


class PersonService:
    def __init__(
        self,
        identity: IdentityService,
        ledger: AuditLedger,
        tracker: ChangeTracker,
    ) -> None:
        self._identity = identity
        self._ledger = ledger
        self._tracker = tracker

    # -- registration -----------------------------------------------------

    def register(
        self, session: Session, registration: PersonRegistration, actor: ActorContext
    ) -> Person:
        ahvn: Ahvn13 | None = None
        if registration.ahvn13:
            ahvn = Ahvn13.parse(registration.ahvn13)
        elif registration.identification_method is IdentificationMethod.AHVN13:
            raise PersonError(
                "an AHV number is required unless another identification "
                "method is declared"
            )

        if registration.kind is PersonKind.HEALTHCARE_PROFESSIONAL:
            self._validate_professional(session, registration)

        uid = new_uid(self._prefix_for(registration.kind))
        person = Person(
            uid=uid,
            kind=registration.kind.value,
            status=PersonStatus.ACTIVE.value,
            identification_method=registration.identification_method.value,
            birth_date=registration.birth_date,
            administrative_sex=registration.administrative_sex,
            gln=registration.gln,
            profession=registration.profession,
            organization_uid=registration.organization_uid,
        )

        if ahvn is not None:
            derived = self._identity.derive(ahvn)
            existing = session.execute(
                select(Person).where(Person.ppid == derived.ppid)
            ).scalars().first()
            if existing is not None:
                raise DuplicatePersonError(existing.uid)
            person.ppid = derived.ppid
            person.lookup_index = derived.lookup_index
            person.sealed_ahvn = derived.sealed_ahvn
            person.spid = self._allocate_spid(session, ahvn)

        person.given_name_enc = self._identity.seal_field(
            uid, "given_name", registration.given_name
        )
        person.family_name_enc = self._identity.seal_field(
            uid, "family_name", registration.family_name
        )
        if registration.email:
            person.contact_email_enc = self._identity.seal_field(
                uid, "contact_email", registration.email
            )
        if registration.phone:
            person.contact_phone_enc = self._identity.seal_field(
                uid, "contact_phone", registration.phone
            )
        if registration.id_document:
            person.id_document_enc = self._identity.seal_field(
                uid, "id_document", registration.id_document
            )

        session.add(person)
        session.flush()
        self._tracker.record_create(
            session,
            person,
            actor=actor,
            action=AuditAction.PERSON_REGISTERED,
            detail={
                "kind": person.kind,
                "identification_method": person.identification_method,
                "has_ahvn_derived_identity": ahvn is not None,
            },
        )
        return person

    def _allocate_spid(self, session: Session, ahvn: Ahvn13) -> str:
        """Claim a free sector identifier.

        Derivation proposes; the unique constraint disposes. Nine significant
        digits cannot be collision-free at population scale, so a collision is
        expected behaviour rather than an error — we simply try the next
        deterministic candidate.
        """
        for candidate in self._identity.spid_candidates(ahvn):
            taken = session.execute(
                select(Person.uid).where(Person.spid == candidate)
            ).scalars().first()
            if taken is None:
                return candidate
        raise PersonError(
            f"could not allocate a sector identifier after {MAX_SPID_ATTEMPTS} attempts"
        )

    @staticmethod
    def _prefix_for(kind: PersonKind) -> str:
        return {
            PersonKind.PATIENT: "pat",
            PersonKind.HEALTHCARE_PROFESSIONAL: "hcp",
            PersonKind.VISITOR: "vis",
            PersonKind.REPRESENTATIVE: "pat",
        }[kind]

    @staticmethod
    def _validate_professional(
        session: Session, registration: PersonRegistration
    ) -> None:
        if not registration.organization_uid:
            raise PersonError("a healthcare professional must belong to an institution")
        organization = session.get(Organization, registration.organization_uid)
        if organization is None or not organization.active:
            raise PersonError("unknown or inactive institution")
        if registration.gln:
            from ehealth.domain.uid import is_valid_gtin

            # A GLN is a GTIN-13 and carries the same check digit.
            if not is_valid_gtin(registration.gln):
                raise PersonError("GLN check digit is wrong")

    # -- lookup -----------------------------------------------------------

    def find_by_ahvn(self, session: Session, ahvn13: str) -> Person | None:
        """Resolve a person by AHV number without ever storing it.

        Matching on the pseudonym rather than the blind index means the answer
        stays correct across an index-key rotation.
        """
        ahvn = Ahvn13.parse(ahvn13)
        return (
            session.execute(
                select(Person).where(Person.ppid == self._identity.ppid(ahvn))
            )
            .scalars()
            .first()
        )

    def find_by_spid(self, session: Session, spid: str) -> Person | None:
        digits = spid.replace(".", "")
        return (
            session.execute(select(Person).where(Person.spid == digits))
            .scalars()
            .first()
        )

    def get(self, session: Session, person_uid: str) -> Person:
        person = session.get(Person, person_uid)
        if person is None:
            raise PersonError("unknown person")
        return person

    # -- presentation -----------------------------------------------------

    def view(self, person: Person) -> PersonView:
        """Decrypt the direct identifiers. Callers must have authorised the
        read already; this method does not check permissions."""

        def open_field(field: str, envelope: str | None) -> str | None:
            if envelope is None:
                return None
            return self._identity.open_field(person.uid, field, envelope)

        return PersonView(
            uid=person.uid,
            kind=person.kind,
            status=person.status,
            spid=person.spid,
            given_name=open_field("given_name", person.given_name_enc),
            family_name=open_field("family_name", person.family_name_enc),
            birth_date=person.birth_date,
            administrative_sex=person.administrative_sex,
            email=open_field("contact_email", person.contact_email_enc),
            phone=open_field("contact_phone", person.contact_phone_enc),
            gln=person.gln,
            profession=person.profession,
            organization_uid=person.organization_uid,
            identification_method=person.identification_method,
            version=person.version,
        )

    # -- mutation ---------------------------------------------------------

    def update_contact(
        self,
        session: Session,
        person: Person,
        actor: ActorContext,
        *,
        email: str | None = None,
        phone: str | None = None,
        status: PersonStatus | None = None,
        reason: str | None = None,
    ) -> Person:
        before = snapshot(person)
        if email is not None:
            person.contact_email_enc = self._identity.seal_field(
                person.uid, "contact_email", email
            )
        if phone is not None:
            person.contact_phone_enc = self._identity.seal_field(
                person.uid, "contact_phone", phone
            )
        if status is not None:
            person.status = status.value
        self._tracker.record_update(
            session,
            person,
            before,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            reason=reason,
        )
        return person

    # -- controlled re-identification -------------------------------------

    def disclose_ahvn(
        self, session: Session, person: Person, actor: ActorContext, *, legal_basis: str
    ) -> str:
        """Recover the AHV number under a stated legal basis.

        The audit entry is written *before* the decryption, so an aborted or
        crashing disclosure still leaves a trace.
        """
        if not legal_basis.strip():
            raise PersonError("a legal basis must be recorded for disclosure")
        if person.sealed_ahvn is None or person.ppid is None:
            raise PersonError("no AHV number is retained for this person")
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.AHVN_UNSEALED,
            resource_type="person",
            resource_uid=person.uid,
            detail={"legal_basis": legal_basis[:500]},
        )
        return self._identity.unseal(person.sealed_ahvn, person.ppid).formatted()


class OrganizationService:
    def __init__(self, ledger: AuditLedger, tracker: ChangeTracker) -> None:
        self._ledger = ledger
        self._tracker = tracker

    def register(
        self,
        session: Session,
        actor: ActorContext,
        *,
        name: str,
        che_uid: str | None = None,
        gln: str | None = None,
        kind: str = "practice",
        community: str | None = None,
    ) -> Organization:
        digits = None
        if che_uid:
            try:
                digits = CheUid.parse(che_uid).digits
            except IdentifierError as exc:
                raise PersonError(str(exc)) from exc
            duplicate = session.execute(
                select(Organization).where(Organization.che_uid == digits)
            ).scalars().first()
            if duplicate is not None:
                raise PersonError("an institution with this CHE UID already exists")

        organization = Organization(
            uid=new_uid("org"),
            che_uid=digits,
            gln=gln,
            name=name,
            kind=kind,
            community=community,
        )
        session.add(organization)
        try:
            session.flush()
        except IntegrityError as exc:
            raise PersonError("institution conflicts with an existing record") from exc
        self._tracker.record_create(
            session,
            organization,
            actor=actor,
            action=AuditAction.PERSON_REGISTERED,
            detail={"resource": "organization", "name": name},
        )
        return organization

    @staticmethod
    def get(session: Session, uid: str) -> Organization:
        Uid.parse_typed(uid, "org")
        organization = session.get(Organization, uid)
        if organization is None:
            raise PersonError("unknown institution")
        return organization
