# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Person registration, pseudonymisation at rest, dossier and medication."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from ehealth.models.core import IdentificationMethod, PersonKind
from ehealth.services.dossier import DossierError
from ehealth.services.medication import MedicationError, ProductInput
from ehealth.services.persons import (
    DuplicatePersonError,
    PersonError,
    PersonRegistration,
)

from tests.conftest import AHVN_ANNA, AHVN_DORA


def register_patient(container, db, actor, ahvn=AHVN_DORA, **overrides):
    fields = dict(
        kind=PersonKind.PATIENT,
        given_name="Dora",
        family_name="Beispiel",
        ahvn13=ahvn,
    )
    fields.update(overrides)
    return container.persons.register(db, PersonRegistration(**fields), actor)


class TestRegistration:
    def test_assigns_a_typed_uid_and_sector_id(self, container, db, system_actor):
        person = register_patient(container, db, system_actor)
        assert person.uid.startswith("pat_")
        assert person.spid and person.spid.startswith("761")
        assert person.ppid

    def test_never_stores_the_ahv_number_in_a_queryable_column(
        self, container, db, system_actor
    ):
        """The whole point of the design: a database dump must not contain the
        AHV number anywhere it could be joined on."""
        register_patient(container, db, system_actor, ahvn=AHVN_ANNA)
        db.commit()
        digits = AHVN_ANNA.replace(".", "")
        rows = db.execute(text("SELECT * FROM person")).mappings().all()
        for row in rows:
            for column, value in row.items():
                assert digits not in str(value), f"AHVN13 leaked into {column}"
                assert AHVN_ANNA not in str(value), f"AHVN13 leaked into {column}"

    def test_names_are_encrypted_at_rest(self, container, db, system_actor):
        register_patient(container, db, system_actor, family_name="Hufschmid")
        db.commit()
        rows = db.execute(text("SELECT * FROM person")).mappings().all()
        assert not any("Hufschmid" in str(v) for row in rows for v in row.values())

    def test_view_decrypts_for_an_authorised_caller(self, container, db, system_actor):
        person = register_patient(container, db, system_actor, family_name="Hufschmid")
        view = container.persons.view(person)
        assert view.family_name == "Hufschmid"
        assert view.given_name == "Dora"

    def test_rejects_a_duplicate_ahv_number(self, container, db, system_actor, world):
        with pytest.raises(DuplicatePersonError) as excinfo:
            register_patient(container, db, system_actor, ahvn=AHVN_ANNA)
        assert excinfo.value.existing_uid == world.patient.uid

    def test_finds_a_person_by_ahv_number_without_storing_it(
        self, container, db, system_actor, world
    ):
        found = container.persons.find_by_ahvn(db, AHVN_ANNA)
        assert found is not None
        assert found.uid == world.patient.uid

    def test_finds_a_person_by_sector_id_in_either_format(
        self, container, db, world
    ):
        from ehealth.domain.uid import format_spid

        spid = world.patient.spid
        assert container.persons.find_by_spid(db, spid).uid == world.patient.uid
        assert (
            container.persons.find_by_spid(db, format_spid(spid)).uid
            == world.patient.uid
        )

    def test_allocates_distinct_sector_ids(self, container, db, system_actor, world):
        """Nine significant digits collide eventually; allocation must resolve
        it rather than hand two patients the same identifier."""
        other = register_patient(container, db, system_actor)
        assert other.spid != world.patient.spid

    def test_requires_an_alternative_method_when_there_is_no_ahv_number(
        self, container, db, system_actor
    ):
        with pytest.raises(PersonError, match="AHV number is required"):
            container.persons.register(
                db,
                PersonRegistration(
                    kind=PersonKind.PATIENT, given_name="Sans", family_name="Numero"
                ),
                system_actor,
            )

    def test_registers_a_cross_border_patient_without_an_ahv_number(
        self, container, db, system_actor
    ):
        person = container.persons.register(
            db,
            PersonRegistration(
                kind=PersonKind.PATIENT,
                given_name="Jean",
                family_name="Voyageur",
                identification_method=IdentificationMethod.PASSPORT,
                id_document="X1234567",
            ),
            system_actor,
        )
        assert person.uid.startswith("pat_")
        assert person.ppid is None
        assert person.spid is None
        assert person.identification_method == "passport"

    def test_a_professional_must_belong_to_an_institution(
        self, container, db, system_actor
    ):
        with pytest.raises(PersonError, match="institution"):
            container.persons.register(
                db,
                PersonRegistration(
                    kind=PersonKind.HEALTHCARE_PROFESSIONAL,
                    given_name="Frei",
                    family_name="Schaffend",
                    ahvn13=AHVN_DORA,
                ),
                system_actor,
            )

    def test_rejects_a_bad_gln(self, container, db, system_actor, world):
        with pytest.raises(PersonError, match="GLN"):
            container.persons.register(
                db,
                PersonRegistration(
                    kind=PersonKind.HEALTHCARE_PROFESSIONAL,
                    given_name="Falsch",
                    family_name="Nummer",
                    ahvn13=AHVN_DORA,
                    gln="7601000000003",
                    organization_uid=world.organization.uid,
                ),
                system_actor,
            )

    def test_visitors_get_a_visitor_prefixed_uid(self, container, db, world):
        assert world.visitor.uid.startswith("vis_")


class TestDisclosure:
    def test_requires_a_legal_basis(self, container, db, system_actor, world):
        with pytest.raises(PersonError, match="legal basis"):
            container.persons.disclose_ahvn(
                db, world.patient, system_actor, legal_basis="  "
            )

    def test_recovers_the_number_and_audits_it(
        self, container, db, system_actor, world
    ):
        from ehealth.models.audit import AuditEvent

        revealed = container.persons.disclose_ahvn(
            db, world.patient, system_actor, legal_basis="court order 2026/42"
        )
        assert revealed == AHVN_ANNA
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "person.ahvn_unsealed")
        ).scalars().one()
        assert event.detail["legal_basis"] == "court order 2026/42"
        assert AHVN_ANNA not in str(event.detail)

    def test_fails_when_nothing_was_retained(self, container, db, system_actor, world):
        world.patient.sealed_ahvn = None
        with pytest.raises(PersonError, match="no AHV number is retained"):
            container.persons.disclose_ahvn(
                db, world.patient, system_actor, legal_basis="court order"
            )


class TestDossier:
    def test_opens_with_a_retention_horizon(self, container, db, world):
        assert world.dossier.retention_until is not None
        assert world.dossier.retention_until > world.dossier.opened_at

    def test_refuses_a_second_dossier(self, container, db, system_actor, world):
        with pytest.raises(DossierError, match="already has a dossier"):
            container.dossiers.open(db, system_actor, patient=world.patient)

    def test_refuses_a_dossier_for_a_non_patient(
        self, container, db, system_actor, world
    ):
        with pytest.raises(DossierError, match="only a patient"):
            container.dossiers.open(db, system_actor, patient=world.doctor)


class TestMedicationCatalogue:
    def test_registers_a_product(self, container, db, system_actor):
        product = container.catalogue.register(
            db,
            system_actor,
            ProductInput(
                gtin="7601000000002",
                name="Dafalgan 500mg",
                atc_code="N02BE01",
                active_ingredient="Paracetamol",
                strength="500 mg",
            ),
        )
        assert product.uid.startswith("med_")

    def test_rejects_a_bad_gtin(self, container, db, system_actor):
        with pytest.raises(MedicationError, match="GTIN"):
            container.catalogue.register(
                db, system_actor, ProductInput(gtin="7601000000003", name="Nope")
            )

    def test_rejects_a_duplicate_gtin(self, container, db, system_actor):
        container.catalogue.register(
            db, system_actor, ProductInput(gtin="7601000000002", name="A")
        )
        with pytest.raises(MedicationError, match="already registered"):
            container.catalogue.register(
                db, system_actor, ProductInput(gtin="7601000000002", name="B")
            )

    def test_searches_by_name_ingredient_atc_and_gtin(
        self, container, db, system_actor
    ):
        container.catalogue.register(
            db,
            system_actor,
            ProductInput(
                gtin="7601000000002",
                name="Dafalgan 500mg",
                active_ingredient="Paracetamol",
                atc_code="N02BE01",
            ),
        )
        db.commit()
        for term in ("Dafalgan", "paracetamol", "N02BE", "7601000000002"):
            assert container.catalogue.search(db, term), term
        assert not container.catalogue.search(db, "Aspirin")
