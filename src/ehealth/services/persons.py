# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Registering and resolving persons, their roles and their credentials.

Every natural person the system touches gets one UID here, and where an AHVN13
exists it is turned into pseudonyms and then dropped. There is no code path
that writes an AHVN13 into a queryable column.

Roles are granted separately from registration, so the physician who is also a
patient is one person holding two roles rather than two records that can drift
apart.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.identity import MAX_SPID_ATTEMPTS, IdentityService
from ehealth.domain.uid import (
    Ahvn13,
    CheUid,
    IdentifierError,
    Uid,
    is_valid_gln,
    is_valid_veka,
    new_uid,
    normalise_zsr,
)
from ehealth.models.audit import AuditAction, ChangeOperation
from ehealth.models.core import (
    CANTONS,
    IdentificationMethod,
    MedicalProfession,
    Organization,
    Person,
    PersonRole,
    PersonRoleKind,
    PersonStatus,
    ProfessionalCredential,
    ProfessionalRegister,
    RoleStatus,
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

    ``roles`` may be empty — a person can exist before anyone decides what they
    are here — but in practice at least one is given at registration.
    """

    given_name: str
    family_name: str
    roles: list[PersonRoleKind] = field(default_factory=list)
    ahvn13: str | None = None
    birth_date: date | None = None
    administrative_sex: str | None = None
    email: str | None = None
    phone: str | None = None
    identification_method: IdentificationMethod = IdentificationMethod.AHVN13
    id_document: str | None = None
    veka_number: str | None = None


@dataclass(slots=True)
class CredentialRegistration:
    """A professional's licence to practise, as Swiss law records it."""

    gln: str
    register: ProfessionalRegister
    profession: MedicalProfession
    specialisation: str | None = None
    licence_canton: str | None = None
    licence_number: str | None = None
    licence_valid_from: date | None = None
    licence_valid_until: date | None = None
    zsr_number: str | None = None
    organization_uid: str | None = None


@dataclass(frozen=True, slots=True)
class PersonView:
    """Decrypted, presentable form of a person. Built only for callers that
    have passed an access check."""

    uid: str
    status: str
    spid: str | None
    roles: tuple[str, ...]
    given_name: str | None
    family_name: str | None
    birth_date: date | None
    administrative_sex: str | None
    email: str | None
    phone: str | None
    veka_number: str | None
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
        if registration.veka_number and not is_valid_veka(registration.veka_number):
            raise PersonError("health insurance card number is malformed")

        uid = new_uid("per")
        person = Person(
            uid=uid,
            status=PersonStatus.ACTIVE.value,
            identification_method=registration.identification_method.value,
            birth_date=registration.birth_date,
            administrative_sex=registration.administrative_sex,
        )

        if ahvn is not None:
            derived = self._identity.derive(ahvn)
            existing = (
                session.execute(select(Person).where(Person.ppid == derived.ppid))
                .scalars()
                .first()
            )
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
        for field_name, value in (
            ("contact_email", registration.email),
            ("contact_phone", registration.phone),
            ("id_document", registration.id_document),
            ("veka_number", registration.veka_number),
        ):
            if value:
                setattr(
                    person,
                    f"{field_name}_enc",
                    self._identity.seal_field(uid, field_name, value),
                )

        session.add(person)
        session.flush()
        self._tracker.record_create(
            session,
            person,
            actor=actor,
            action=AuditAction.PERSON_REGISTERED,
            detail={
                "identification_method": person.identification_method,
                "has_ahvn_derived_identity": ahvn is not None,
            },
        )
        for role in dict.fromkeys(registration.roles):
            self.grant_role(session, person, actor, role=role)
        return person

    def _allocate_spid(self, session: Session, ahvn: Ahvn13) -> str:
        """Claim a free EPR-SPID.

        Derivation proposes; the unique constraint disposes. With fourteen
        significant digits a collision is vanishingly unlikely, but the probe
        stays because "unlikely" is not "impossible" and two patients sharing
        an identifier is not a failure mode worth risking.
        """
        for candidate in self._identity.spid_candidates(ahvn):
            taken = (
                session.execute(select(Person.uid).where(Person.spid == candidate))
                .scalars()
                .first()
            )
            if taken is None:
                return candidate
        raise PersonError(
            f"could not allocate an EPR-SPID after {MAX_SPID_ATTEMPTS} attempts"
        )

    # -- roles ------------------------------------------------------------

    def grant_role(
        self,
        session: Session,
        person: Person,
        actor: ActorContext,
        *,
        role: PersonRoleKind,
        valid_until: datetime | None = None,
        note: str | None = None,
    ) -> PersonRole:
        """Grant a role, or revive one that was previously revoked.

        Re-granting reuses the row rather than creating a second one, so the
        history of a role reads as one story instead of several.
        """
        existing = self.role_row(session, person.uid, role)
        if existing is not None:
            if (
                existing.status == RoleStatus.ACTIVE.value
                and existing.valid_until == valid_until
            ):
                return existing
            # Re-granting an active role with a different window adjusts it
            # rather than silently ignoring the new expiry.
            before = snapshot(existing)
            existing.status = RoleStatus.ACTIVE.value
            existing.valid_from = utcnow()
            existing.valid_until = valid_until
            existing.granted_by_uid = actor.actor_uid
            self._tracker.record_update(
                session,
                existing,
                before,
                actor=actor,
                action=AuditAction.PERSON_UPDATED,
                operation=ChangeOperation.STATUS_CHANGE,
                reason=note or "role re-granted",
            )
            return existing

        assignment = PersonRole(
            uid=new_uid("crd"),
            person_uid=person.uid,
            role=role.value,
            status=RoleStatus.ACTIVE.value,
            valid_from=utcnow(),
            valid_until=valid_until,
            granted_by_uid=actor.actor_uid,
            note=note,
        )
        session.add(assignment)
        session.flush()
        self._tracker.record_create(
            session,
            assignment,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            detail={"person_uid": person.uid, "role": role.value},
        )
        return assignment

    def revoke_role(
        self,
        session: Session,
        person: Person,
        actor: ActorContext,
        *,
        role: PersonRoleKind,
        reason: str,
        suspend_only: bool = False,
    ) -> PersonRole:
        assignment = self.role_row(session, person.uid, role)
        if assignment is None:
            raise PersonError("this person does not hold that role")
        before = snapshot(assignment)
        assignment.status = (
            RoleStatus.SUSPENDED.value if suspend_only else RoleStatus.REVOKED.value
        )
        assignment.valid_until = utcnow()
        self._tracker.record_update(
            session,
            assignment,
            before,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            operation=ChangeOperation.STATUS_CHANGE,
            reason=reason,
        )
        return assignment

    @staticmethod
    def role_row(
        session: Session, person_uid: str, role: PersonRoleKind
    ) -> PersonRole | None:
        return (
            session.execute(
                select(PersonRole).where(
                    PersonRole.person_uid == person_uid,
                    PersonRole.role == role.value,
                )
            )
            .scalars()
            .first()
        )

    @staticmethod
    def roles(session: Session, person_uid: str) -> list[PersonRole]:
        return list(
            session.execute(
                select(PersonRole).where(PersonRole.person_uid == person_uid)
            ).scalars()
        )

    def has_role(
        self,
        session: Session,
        person_uid: str,
        role: PersonRoleKind,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Whether the person may act in this role *right now*.

        The one authority question in the system for roles. Callers must never
        infer it from a UID prefix or a stored label.
        """
        assignment = self.role_row(session, person_uid, role)
        return assignment is not None and assignment.is_live(now or utcnow())

    def require_role(
        self, session: Session, person_uid: str, role: PersonRoleKind
    ) -> None:
        if not self.has_role(session, person_uid, role):
            raise PersonError(f"person does not hold an active {role.value} role")

    # -- professional credentials -----------------------------------------

    def register_credential(
        self,
        session: Session,
        person: Person,
        actor: ActorContext,
        credential: CredentialRegistration,
    ) -> ProfessionalCredential:
        """Record a professional's GLN, register entry and practice licence.

        Granting the professional role is part of this rather than a separate
        step: a healthcare professional without a credential is exactly the
        state this model exists to make impossible.
        """
        if not is_valid_gln(credential.gln):
            raise PersonError("GLN check digit is wrong")
        duplicate = (
            session.execute(
                select(ProfessionalCredential).where(
                    ProfessionalCredential.gln == credential.gln
                )
            )
            .scalars()
            .first()
        )
        if duplicate is not None:
            raise PersonError("this GLN is already registered to a person")

        canton = credential.licence_canton
        if canton is not None:
            canton = canton.strip().upper()
            if canton not in CANTONS:
                raise PersonError(f"unknown canton {canton!r}")

        zsr = normalise_zsr(credential.zsr_number) if credential.zsr_number else None

        if credential.organization_uid is not None:
            organization = session.get(Organization, credential.organization_uid)
            if organization is None or not organization.active:
                raise PersonError("unknown or inactive institution")

        record = ProfessionalCredential(
            uid=new_uid("crd"),
            person_uid=person.uid,
            gln=credential.gln,
            register=credential.register.value,
            profession=credential.profession.value,
            specialisation=credential.specialisation,
            licence_canton=canton,
            licence_number=credential.licence_number,
            licence_valid_from=credential.licence_valid_from,
            licence_valid_until=credential.licence_valid_until,
            zsr_number=zsr,
            organization_uid=credential.organization_uid,
        )
        session.add(record)
        session.flush()
        self._tracker.record_create(
            session,
            record,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            detail={
                "person_uid": person.uid,
                "gln": credential.gln,
                "register": record.register,
                "profession": record.profession,
            },
        )
        self.grant_role(
            session,
            person,
            actor,
            role=PersonRoleKind.HEALTHCARE_PROFESSIONAL,
            note=f"credential {record.uid}",
        )
        return record

    def verify_credential(
        self,
        session: Session,
        credential: ProfessionalCredential,
        actor: ActorContext,
        *,
        source: str,
        evidence: dict | None = None,
    ) -> ProfessionalCredential:
        """Record that the credential was checked against its register.

        The check itself is out of scope — MedReg, NAREG, PsyReg and Refdata
        each expose their own interface, and none of them belongs inside this
        module. What belongs here is the *evidence*: who checked, against
        what, and when, so that "we were told" and "we verified" never look
        alike in the record.
        """
        if not source.strip():
            raise PersonError("a verification source must be named")
        before = snapshot(credential)
        credential.verified_at = utcnow()
        credential.verification_source = source[:80]
        credential.verification_evidence = evidence or {}
        self._tracker.record_update(
            session,
            credential,
            before,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            reason=f"credential verified against {source[:60]}",
        )
        return credential

    def suspend_credential(
        self,
        session: Session,
        credential: ProfessionalCredential,
        actor: ActorContext,
        *,
        reason: str,
    ) -> ProfessionalCredential:
        """Suspend the practice licence. Prescribing authority stops at once."""
        before = snapshot(credential)
        credential.licence_suspended = True
        self._tracker.record_update(
            session,
            credential,
            before,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            operation=ChangeOperation.STATUS_CHANGE,
            reason=reason,
        )
        return credential

    @staticmethod
    def credentials(session: Session, person_uid: str) -> list[ProfessionalCredential]:
        return list(
            session.execute(
                select(ProfessionalCredential).where(
                    ProfessionalCredential.person_uid == person_uid
                )
            ).scalars()
        )

    def active_credential(
        self, session: Session, person_uid: str, *, on: date | None = None
    ) -> ProfessionalCredential | None:
        """The credential that currently carries authority, if any.

        Where a professional holds several — practising in two cantons, say —
        the one with a live licence wins, and a verified one is preferred over
        an unverified one.
        """
        on = on or utcnow().date()
        live = [
            c for c in self.credentials(session, person_uid) if c.licence_is_live(on)
        ]
        if not live:
            return None
        return sorted(live, key=lambda c: (c.is_verified, c.uid), reverse=True)[0]

    def find_by_gln(self, session: Session, gln: str) -> ProfessionalCredential | None:
        return (
            session.execute(
                select(ProfessionalCredential).where(ProfessionalCredential.gln == gln)
            )
            .scalars()
            .first()
        )

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
        digits = (spid or "").replace(".", "").replace(" ", "")
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

    def view(self, session: Session, person: Person) -> PersonView:
        """Decrypt the direct identifiers. Callers must have authorised the
        read already; this method does not check permissions."""

        def open_field(field_name: str, envelope: str | None) -> str | None:
            if envelope is None:
                return None
            return self._identity.open_field(person.uid, field_name, envelope)

        now = utcnow()
        return PersonView(
            uid=person.uid,
            status=person.status,
            spid=person.spid,
            roles=tuple(
                sorted(
                    r.role for r in self.roles(session, person.uid) if r.is_live(now)
                )
            ),
            given_name=open_field("given_name", person.given_name_enc),
            family_name=open_field("family_name", person.family_name_enc),
            birth_date=person.birth_date,
            administrative_sex=person.administrative_sex,
            email=open_field("contact_email", person.contact_email_enc),
            phone=open_field("contact_phone", person.contact_phone_enc),
            veka_number=open_field("veka_number", person.veka_number_enc),
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
        zsr_number: str | None = None,
        canton: str | None = None,
    ) -> Organization:
        digits = None
        if che_uid:
            try:
                digits = CheUid.parse(che_uid).digits
            except IdentifierError as exc:
                raise PersonError(str(exc)) from exc
            duplicate = (
                session.execute(
                    select(Organization).where(Organization.che_uid == digits)
                )
                .scalars()
                .first()
            )
            if duplicate is not None:
                raise PersonError("an institution with this CHE UID already exists")
        if gln and not is_valid_gln(gln):
            raise PersonError("institution GLN check digit is wrong")
        if canton is not None:
            canton = canton.strip().upper()
            if canton not in CANTONS:
                raise PersonError(f"unknown canton {canton!r}")

        organization = Organization(
            uid=new_uid("org"),
            che_uid=digits,
            gln=gln,
            name=name,
            kind=kind,
            community=community,
            zsr_number=normalise_zsr(zsr_number) if zsr_number else None,
            canton=canton,
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
