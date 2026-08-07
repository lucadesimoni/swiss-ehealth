# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Multiple roles per person, Swiss professional credentials, and the
prescribing authority that follows from them.

The case that drives this file: a physician is also somebody's patient. A
model that makes role a property of the person forces them into two records
with two pseudonyms, and then the patient's own doctor cannot see the record.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from ehealth.db import utcnow
from ehealth.models.base import Purpose
from ehealth.models.clinical import (
    DispensingCategory,
    MedicationEventKind,
    NarcoticSchedule,
)
from ehealth.models.core import (
    MedicalProfession,
    PersonRoleKind,
    ProfessionalRegister,
    RoleStatus,
)
from ehealth.security.tokens import Scope
from ehealth.services.access import AccessError
from ehealth.services.medication import MedicationError, ProductInput, StatementInput
from ehealth.services.persons import (
    CredentialRegistration,
    PersonError,
    PersonRegistration,
)

from tests.conftest import AHVN_DORA


def register(container, db, actor, ahvn=AHVN_DORA, roles=(), **overrides):
    fields = dict(
        roles=list(roles),
        given_name="Dora",
        family_name="Beispiel",
        ahvn13=ahvn,
    )
    fields.update(overrides)
    return container.persons.register(db, PersonRegistration(**fields), actor)


def credential_for(container, db, actor, person, **overrides):
    fields = dict(
        gln="7602000000009",
        register=ProfessionalRegister.MEDREG,
        profession=MedicalProfession.PHYSICIAN,
        licence_canton="BE",
        licence_number="BE-2020-1",
    )
    fields.update(overrides)
    return container.persons.register_credential(
        db, person, actor, CredentialRegistration(**fields)
    )


class TestMultipleRoles:
    def test_a_doctor_can_also_be_a_patient(self, container, db, world):
        """The whole point: one person, one UID, one pseudonym, two roles."""
        roles = {
            r.role for r in container.persons.roles(db, world.doctor.uid) if r.is_live(utcnow())
        }
        assert roles == {"patient", "healthcare_professional"}
        assert world.doctor.uid.startswith("per_")
        assert world.doctor.ppid is not None

    def test_granting_a_role_is_idempotent(self, container, db, system_actor, world):
        first = container.persons.grant_role(
            db, world.patient, system_actor, role=PersonRoleKind.PATIENT
        )
        second = container.persons.grant_role(
            db, world.patient, system_actor, role=PersonRoleKind.PATIENT
        )
        assert first.uid == second.uid

    def test_a_revoked_role_can_be_revived_on_the_same_row(
        self, container, db, system_actor, world
    ):
        """One story per role, not several — the history has to read."""
        original = container.persons.role_row(
            db, world.visitor.uid, PersonRoleKind.VISITOR
        )
        container.persons.revoke_role(
            db,
            world.visitor,
            system_actor,
            role=PersonRoleKind.VISITOR,
            reason="visit ended",
        )
        revived = container.persons.grant_role(
            db, world.visitor, system_actor, role=PersonRoleKind.VISITOR
        )
        assert revived.uid == original.uid
        assert revived.status == RoleStatus.ACTIVE.value

    def test_revoking_removes_the_authority_immediately(
        self, container, db, system_actor, world
    ):
        assert container.persons.has_role(
            db, world.doctor.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        )
        container.persons.revoke_role(
            db,
            world.doctor,
            system_actor,
            role=PersonRoleKind.HEALTHCARE_PROFESSIONAL,
            reason="left the profession",
        )
        assert not container.persons.has_role(
            db, world.doctor.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        )

    def test_an_expired_role_stops_counting(self, container, db, system_actor, world):
        container.persons.grant_role(
            db,
            world.visitor,
            system_actor,
            role=PersonRoleKind.VISITOR,
            valid_until=utcnow() - timedelta(minutes=1),
        )
        assert not container.persons.has_role(
            db, world.visitor.uid, PersonRoleKind.VISITOR
        )

    def test_require_role_refuses_a_role_not_held(self, container, db, world):
        with pytest.raises(PersonError, match="healthcare_professional"):
            container.persons.require_role(
                db, world.patient.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
            )

    def test_the_view_lists_only_live_roles(self, container, db, system_actor, world):
        container.persons.revoke_role(
            db,
            world.doctor,
            system_actor,
            role=PersonRoleKind.PATIENT,
            reason="administrative correction",
        )
        assert container.persons.view(db, world.doctor).roles == (
            "healthcare_professional",
        )


class TestCredentials:
    def test_registering_a_credential_grants_the_professional_role(
        self, container, db, system_actor
    ):
        """A professional without a credential is the state this prevents."""
        person = register(container, db, system_actor)
        assert not container.persons.has_role(
            db, person.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        )
        credential_for(container, db, system_actor, person)
        assert container.persons.has_role(
            db, person.uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        )

    def test_a_gln_belongs_to_one_person(self, container, db, system_actor, world):
        person = register(container, db, system_actor)
        with pytest.raises(PersonError, match="already registered"):
            credential_for(
                container, db, system_actor, person, gln=world.credential.gln
            )

    def test_rejects_an_unknown_canton(self, container, db, system_actor):
        person = register(container, db, system_actor)
        with pytest.raises(PersonError, match="canton"):
            credential_for(container, db, system_actor, person, licence_canton="XX")

    def test_normalises_the_zsr_number(self, container, db, system_actor):
        person = register(container, db, system_actor)
        credential = credential_for(
            container, db, system_actor, person, zsr_number="a.654321"
        )
        assert credential.zsr_number == "A654321"

    def test_verification_is_recorded_with_its_source(
        self, container, db, system_actor, world
    ):
        """"We were told" and "we checked" must never look the same."""
        person = register(container, db, system_actor)
        credential = credential_for(container, db, system_actor, person)
        assert credential.is_verified is False

        container.persons.verify_credential(
            db, credential, system_actor, source="MedReg", evidence={"ref": "x"}
        )
        assert credential.is_verified
        assert credential.verification_source == "MedReg"

    def test_verification_needs_a_named_source(
        self, container, db, system_actor, world
    ):
        with pytest.raises(PersonError, match="source"):
            container.persons.verify_credential(
                db, world.credential, system_actor, source="  "
            )

    def test_a_live_licence_carries_prescribing_authority(self, world):
        assert world.credential.may_prescribe(date.today())

    def test_an_expired_licence_does_not(self, container, db, system_actor):
        person = register(container, db, system_actor)
        credential = credential_for(
            container,
            db,
            system_actor,
            person,
            licence_valid_until=date.today() - timedelta(days=1),
        )
        assert not credential.may_prescribe(date.today())

    def test_a_suspended_licence_does_not(
        self, container, db, system_actor, world
    ):
        container.persons.suspend_credential(
            db, world.credential, system_actor, reason="disciplinary measure"
        )
        assert not world.credential.may_prescribe(date.today())

    def test_a_nurse_does_not_prescribe(self, container, db, system_actor):
        person = register(container, db, system_actor)
        credential = credential_for(
            container,
            db,
            system_actor,
            person,
            register=ProfessionalRegister.NAREG,
            profession=MedicalProfession.NURSE,
        )
        assert not credential.may_prescribe(date.today())

    def test_institutional_staff_never_prescribe(self, container, db, system_actor):
        """Not in a federal register, so no prescribing authority whatever the
        job title says."""
        person = register(container, db, system_actor)
        credential = credential_for(
            container,
            db,
            system_actor,
            person,
            register=ProfessionalRegister.INSTITUTIONAL,
            profession=MedicalProfession.PHYSICIAN,
        )
        assert not credential.may_prescribe(date.today())

    def test_a_credential_without_a_canton_grants_nothing(
        self, container, db, system_actor
    ):
        person = register(container, db, system_actor)
        credential = credential_for(
            container, db, system_actor, person, licence_canton=None
        )
        assert not credential.licence_is_live(date.today())
        assert not credential.may_prescribe(date.today())

    def test_lookup_by_gln(self, container, db, world):
        found = container.persons.find_by_gln(db, world.credential.gln)
        assert found is not None
        assert found.person_uid == world.doctor.uid


class TestPrescribingAuthority:
    """HMG art. 24 ff., enforced where it matters: at the write."""

    @pytest.fixture
    def doctor_access(self, container, db, system_actor, world):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.MEDICATION_READ, Scope.MEDICATION_WRITE],
        )
        capability = container.access.mint(db, system_actor, grant=grant)
        db.commit()
        return container.access.authorize(
            db, capability.token, required_scope=Scope.MEDICATION_WRITE
        )

    @pytest.fixture
    def prescription_only_product(self, container, db, system_actor):
        return container.catalogue.register(
            db,
            system_actor,
            ProductInput(
                gtin="7601000000002",
                name="Lisinopril 10 mg",
                swissmedic_authorisation="62536",
                atc_code="C09AA03",
                dispensing_category=DispensingCategory.B,
            ),
        )

    def test_a_licensed_doctor_may_prescribe(
        self, container, db, world, doctor_access, prescription_only_product
    ):
        statement = container.medications.record(
            db,
            doctor_access,
            StatementInput(
                kind=MedicationEventKind.PRESCRIPTION,
                product_uid=prescription_only_product.uid,
            ),
            recorded_by_uid=world.doctor.uid,
        )
        # The prescription carries the licence it was written under.
        assert statement.recorded_by_gln == world.credential.gln
        assert statement.recorded_under_credential_uid == world.credential.uid

    def test_a_suspended_licence_stops_prescribing_at_once(
        self,
        container,
        db,
        system_actor,
        world,
        doctor_access,
        prescription_only_product,
    ):
        container.persons.suspend_credential(
            db, world.credential, system_actor, reason="disciplinary measure"
        )
        db.flush()
        with pytest.raises(MedicationError, match="live practice licence"):
            container.medications.record(
                db,
                doctor_access,
                StatementInput(
                    kind=MedicationEventKind.PRESCRIPTION,
                    product_uid=prescription_only_product.uid,
                ),
                recorded_by_uid=world.doctor.uid,
            )

    def test_a_patient_cannot_write_themselves_a_prescription(
        self, container, db, world, doctor_access, prescription_only_product
    ):
        with pytest.raises(MedicationError, match="healthcare professional"):
            container.medications.record(
                db,
                doctor_access,
                StatementInput(
                    kind=MedicationEventKind.PRESCRIPTION,
                    product_uid=prescription_only_product.uid,
                ),
                recorded_by_uid=world.patient.uid,
            )

    def test_a_patient_may_record_their_own_medication(
        self, container, db, world, doctor_access
    ):
        """A complete medication list is worth more than a tidy one."""
        statement = container.medications.record(
            db,
            doctor_access,
            StatementInput(
                kind=MedicationEventKind.SELF_REPORTED,
                product_text="Magnesium, aus der Drogerie",
            ),
            recorded_by_uid=world.patient.uid,
        )
        assert statement.recorded_by_gln is None

    def test_a_nurse_may_administer_but_not_prescribe(
        self, container, db, system_actor, world, doctor_access, prescription_only_product
    ):
        nurse = register(container, db, system_actor)
        credential_for(
            container,
            db,
            system_actor,
            nurse,
            gln="7603000000006",
            register=ProfessionalRegister.NAREG,
            profession=MedicalProfession.NURSE,
        )
        db.flush()
        with pytest.raises(MedicationError, match="prescribing authority"):
            container.medications.record(
                db,
                doctor_access,
                StatementInput(
                    kind=MedicationEventKind.PRESCRIPTION,
                    product_uid=prescription_only_product.uid,
                ),
                recorded_by_uid=nurse.uid,
            )

    def test_a_withdrawn_product_cannot_be_prescribed(
        self, container, db, system_actor, world, doctor_access
    ):
        from ehealth.models.clinical import AuthorisationStatus

        withdrawn = container.catalogue.register(
            db,
            system_actor,
            ProductInput(
                gtin="7602000000009",
                name="Vom Markt genommen",
                authorisation_status=AuthorisationStatus.WITHDRAWN,
            ),
        )
        with pytest.raises(MedicationError, match="not authorised"):
            container.medications.record(
                db,
                doctor_access,
                StatementInput(
                    kind=MedicationEventKind.PRESCRIPTION, product_uid=withdrawn.uid
                ),
                recorded_by_uid=world.doctor.uid,
            )

    def test_the_trail_flags_narcotics_for_a_betmg_audit(
        self, container, db, system_actor, world, doctor_access
    ):
        from sqlalchemy import select

        from ehealth.models.audit import AuditEvent

        opioid = container.catalogue.register(
            db,
            system_actor,
            ProductInput(
                gtin="7602000000009",
                name="Morphin HCl 10 mg",
                atc_code="N02AA01",
                dispensing_category=DispensingCategory.A,
                narcotic_schedule=NarcoticSchedule.A,
            ),
        )
        container.medications.record(
            db,
            doctor_access,
            StatementInput(
                kind=MedicationEventKind.PRESCRIPTION, product_uid=opioid.uid
            ),
            recorded_by_uid=world.doctor.uid,
        )
        db.commit()
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "medication.added")
        ).scalars().one()
        assert event.detail["narcotic_schedule"] == "a"
        assert event.detail["dispensing_category"] == "A"
        assert event.detail["prescriber_gln"] == world.credential.gln
        assert event.detail["credential_verified"] is False


class TestGrantCapacity:
    def test_a_grant_names_the_capacity_it_was_issued_under(
        self, container, db, system_actor, world
    ):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ],
        )
        assert grant.grantee_kind == PersonRoleKind.HEALTHCARE_PROFESSIONAL.value

    def test_a_grant_refuses_a_capacity_the_grantee_lacks(
        self, container, db, system_actor, world
    ):
        with pytest.raises(AccessError, match="visitor role"):
            container.access.issue_grant(
                db,
                system_actor,
                dossier=world.dossier,
                grantee=world.doctor,
                granted_by=world.patient,
                purpose=Purpose.TREATMENT,
                scopes=[Scope.DOSSIER_READ],
                grantee_role=PersonRoleKind.VISITOR,
            )

    def test_losing_the_role_kills_a_live_token(
        self, container, db, system_actor, world
    ):
        """A doctor struck off yesterday does not get in today, whatever token
        they are holding."""
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ],
        )
        capability = container.access.mint(db, system_actor, grant=grant)
        db.commit()
        container.access.authorize(
            db, capability.token, required_scope=Scope.DOSSIER_READ
        )

        container.persons.revoke_role(
            db,
            world.doctor,
            system_actor,
            role=PersonRoleKind.HEALTHCARE_PROFESSIONAL,
            reason="struck off",
        )
        db.commit()
        with pytest.raises(AccessError):
            container.access.authorize(
                db, capability.token, required_scope=Scope.DOSSIER_READ
            )
