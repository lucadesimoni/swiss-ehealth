# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""IHE PIXm (ITI-83) and PDQm (ITI-78) over FHIR, per the CH EPR FHIR guide.

Each error case asserts the HTTP status and FHIR issue code the profile
prescribes, because a conformance tool checks exactly those, and a partner
system branches on them.
"""

from __future__ import annotations

import json
from datetime import date

import pytest
from sqlalchemy import select

from ehealth.db import get_session_factory
from ehealth.domain.identity import normalise_family_name
from ehealth.models.audit import AuditAction, AuditEvent
from ehealth.models.core import IdentificationMethod, Person, PersonRoleKind
from ehealth.scripts.reindex_demographics import reindex
from ehealth.services.patient_directory import (
    AHVN13_OID,
    EPR_SPID_OID,
    DirectoryError,
    PatientDirectory,
)
from ehealth.services.persons import PersonRegistration
from tests.conftest import login

COMMUNITY = "2.999.756.1"
SPID = f"urn:oid:{EPR_SPID_OID}"
LOCAL = f"urn:oid:{COMMUNITY}"
FHIR_JSON = "application/fhir+json"

#: Valid AHVN13s (EAN-13 check digit) not used elsewhere in the suite.
AHVN_ERIKA = "756.5555.5555.57"
AHVN_ERIK = "756.4444.4444.46"


@pytest.fixture
def patients(container, db, system_actor):
    """Patients with the demographics a search needs."""

    def register(given, family, born, sex, ahvn=None):
        return container.persons.register(
            db,
            PersonRegistration(
                roles=[PersonRoleKind.PATIENT],
                given_name=given,
                family_name=family,
                birth_date=born,
                administrative_sex=sex,
                ahvn13=ahvn,
                identification_method=(
                    IdentificationMethod.AHVN13
                    if ahvn
                    else IdentificationMethod.PASSPORT
                ),
                email=f"{given.lower()}@example.ch",
                phone="+41 79 000 00 00",
            ),
            system_actor,
        )

    created = {
        "erika": register("Erika", "Müller", date(1980, 5, 17), "female", AHVN_ERIKA),
        "erik": register("Erik", "Mueller", date(1980, 5, 17), "male", AHVN_ERIK),
        "nospid": register("Nora", "Keller", date(1975, 1, 2), "female"),
    }
    db.commit()
    return created


@pytest.fixture
def professional(client, mock_idp, outbox, world):
    """A logged-in physician: the world's doctor holds the professional role."""
    session = login(
        client,
        mock_idp,
        outbox,
        person_uid=world.doctor.uid,
        subject="beat-swissid",
        email="beat.arzt@example.ch",
    )
    return {"Authorization": f"Bearer {session.access_token}"}


@pytest.fixture
def patient_only(client, mock_idp, outbox, world):
    session = login(
        client,
        mock_idp,
        outbox,
        person_uid=world.patient.uid,
        subject="anna-swissid",
        email="anna.muster@example.ch",
    )
    return {"Authorization": f"Bearer {session.access_token}"}


def outcome(response) -> dict:
    body = response.json()
    assert body["resourceType"] == "OperationOutcome", body
    return body["issue"][0]


def events(action: AuditAction) -> list[AuditEvent]:
    with get_session_factory()() as session:
        return list(
            session.execute(select(AuditEvent).where(AuditEvent.action == action.value))
            .scalars()
            .all()
        )


class TestAccess:
    def test_an_anonymous_caller_gets_nothing(self, client):
        client.headers.pop("X-Admin-Key", None)
        response = client.get("/v1/fhir/Patient", params={"identifier": "x|y"})
        assert response.status_code == 401

    def test_a_patient_may_not_search_other_patients(
        self, client, patient_only, patients
    ):
        response = client.get(
            "/v1/fhir/Patient",
            params={"family": "Müller", "birthdate": "1980-05-17"},
            headers=patient_only,
        )
        assert response.status_code == 403
        assert outcome(response)["code"] == "forbidden"
        denied = events(AuditAction.ACCESS_DENIED)
        assert denied and denied[-1].resource_type == "patient_directory"

    def test_the_capability_statement_is_public(self, client):
        client.headers.pop("X-Admin-Key", None)
        response = client.get("/v1/fhir/metadata")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(FHIR_JSON)
        body = response.json()
        assert body["fhirVersion"] == "4.0.1"
        (patient,) = body["rest"][0]["resource"]
        assert patient["operation"][0]["name"] == "ihe-pix"


class TestPixm:
    def test_local_id_to_epr_spid(self, client, professional, patients):
        erika = patients["erika"]
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{LOCAL}|{erika.uid}", "targetSystem": SPID},
            headers=professional,
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith(FHIR_JSON)
        parameters = {p["name"]: p for p in response.json()["parameter"]}
        assert parameters["targetIdentifier"]["valueIdentifier"] == {
            "system": SPID,
            "value": erika.spid,
        }
        assert parameters["targetId"]["valueReference"]["reference"] == (
            f"Patient/{erika.uid}"
        )

    def test_epr_spid_to_local_id(self, client, professional, patients):
        erika = patients["erika"]
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{SPID}|{erika.spid}"},
            headers=professional,
        )
        (identifier,) = [
            p["valueIdentifier"]
            for p in response.json()["parameter"]
            if p["name"] == "targetIdentifier"
        ]
        assert identifier == {"system": LOCAL, "value": erika.uid}

    def test_no_identifier_in_the_target_domain_is_an_empty_answer(
        self, client, professional, patients
    ):
        """Not an error: the patient exists, just without an EPR-SPID yet."""
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={
                "sourceIdentifier": f"{LOCAL}|{patients['nospid'].uid}",
                "targetSystem": SPID,
            },
            headers=professional,
        )
        assert response.status_code == 200
        assert response.json() == {"resourceType": "Parameters", "parameter": []}

    def test_an_unknown_source_domain_is_400(self, client, professional):
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": "urn:oid:1.2.3.4|abc"},
            headers=professional,
        )
        assert response.status_code == 400
        assert outcome(response)["diagnostics"] == (
            "sourceIdentifier Assigning Authority not found"
        )

    def test_an_unknown_target_domain_is_403(self, client, professional, patients):
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={
                "sourceIdentifier": f"{LOCAL}|{patients['erika'].uid}",
                "targetSystem": "urn:oid:1.2.3.4",
            },
            headers=professional,
        )
        assert response.status_code == 403
        assert outcome(response)["diagnostics"] == "targetSystem not found"

    def test_an_unknown_patient_is_404(self, client, professional):
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{LOCAL}|per_nobody"},
            headers=professional,
        )
        assert response.status_code == 404
        assert outcome(response)["code"] == "not-found"

    def test_the_ahvn13_is_refused_as_an_identifier(self, client, professional):
        """EPDG art. 5 keeps the AHV number out of the patient record."""
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"urn:oid:{AHVN13_OID}|{AHVN_ERIKA}"},
            headers=professional,
        )
        assert response.status_code == 400
        assert "EPDG art. 5" in outcome(response)["diagnostics"]

    def test_a_visitor_is_not_in_the_patient_directory(
        self, client, professional, world
    ):
        """Indistinguishable from nobody: the directory must not confirm that
        a non-patient exists."""
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{LOCAL}|{world.visitor.uid}"},
            headers=professional,
        )
        assert response.status_code == 404

    def test_a_malformed_identifier_is_400(self, client, professional):
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": "per_x"},
            headers=professional,
        )
        assert response.status_code == 400


class TestPdqm:
    def search(self, client, headers, **params):
        return client.get("/v1/fhir/Patient", params=params, headers=headers)

    def test_by_identifier(self, client, professional, patients):
        erika = patients["erika"]
        response = self.search(client, professional, identifier=f"{SPID}|{erika.spid}")
        assert response.status_code == 200, response.text
        bundle = response.json()
        assert bundle["resourceType"] == "Bundle" and bundle["type"] == "searchset"
        assert bundle["total"] == 1
        (entry,) = bundle["entry"]
        patient = entry["resource"]
        assert entry["fullUrl"].endswith(f"/v1/fhir/Patient/{erika.uid}")
        assert {i["system"] for i in patient["identifier"]} == {SPID, LOCAL}
        assert patient["name"] == [{"family": "Müller", "given": ["Erika"]}]
        assert patient["birthDate"] == "1980-05-17"
        assert patient["gender"] == "female"

    def test_discloses_nothing_beyond_the_patient_resource(
        self, client, professional, patients
    ):
        erika = patients["erika"]
        text = self.search(client, professional, identifier=f"{LOCAL}|{erika.uid}").text
        assert "erika@example.ch" not in text
        assert "+41 79" not in text
        assert AHVN_ERIKA.replace(".", "") not in text.replace(".", "")

    def test_by_family_name_and_birth_date_across_spellings(
        self, client, professional, patients
    ):
        """``Mueller`` finds ``Müller``: the umlaut and its two-letter spelling
        are the same name in Switzerland."""
        bundle = self.search(
            client, professional, family="MUELLER", birthdate="1980-05-17"
        ).json()
        names = sorted(e["resource"]["name"][0]["given"][0] for e in bundle["entry"])
        assert names == ["Erik", "Erika"]

    def test_given_name_and_gender_narrow_the_result(
        self, client, professional, patients
    ):
        by_given = self.search(
            client, professional, family="Müller", birthdate="1980-05-17", given="erika"
        ).json()
        assert by_given["total"] == 1
        by_gender = self.search(
            client, professional, family="Müller", birthdate="1980-05-17", gender="male"
        ).json()
        assert [e["resource"]["name"][0]["given"] for e in by_gender["entry"]] == [
            ["Erik"]
        ]

    def test_family_name_alone_is_too_broad(self, client, professional, patients):
        response = self.search(client, professional, family="Müller")
        assert response.status_code == 400
        assert outcome(response)["code"] == "required"

    def test_a_birth_date_range_is_refused(self, client, professional, patients):
        """A range over birth dates is a listing, not a lookup."""
        response = self.search(
            client, professional, family="Müller", birthdate="ge1980-01-01"
        )
        assert response.status_code == 400

    def test_eq_prefixed_dates_are_accepted(self, client, professional, patients):
        response = self.search(
            client, professional, family="Müller", birthdate="eq1980-05-17"
        )
        assert response.json()["total"] == 2

    def test_no_match_is_an_empty_bundle(self, client, professional, patients):
        bundle = self.search(
            client, professional, family="Nobody", birthdate="2001-01-01"
        ).json()
        assert bundle["total"] == 0 and bundle["entry"] == []

    def test_an_unknown_gender_code_is_400(self, client, professional, patients):
        response = self.search(
            client, professional, family="Müller", birthdate="1980-05-17", gender="m"
        )
        assert response.status_code == 400

    def test_read_by_id(self, client, professional, patients):
        erika = patients["erika"]
        response = client.get(f"/v1/fhir/Patient/{erika.uid}", headers=professional)
        assert response.status_code == 200
        assert response.json()["id"] == erika.uid

    def test_read_of_a_non_patient_is_404(self, client, professional, world):
        response = client.get(
            f"/v1/fhir/Patient/{world.visitor.uid}", headers=professional
        )
        assert response.status_code == 404


class TestAudit:
    def test_searches_are_audited_without_the_search_terms(
        self, client, professional, patients
    ):
        """The audit trail must say who searched and how much they found —
        and must not itself become a list of names and birthdays."""
        client.get(
            "/v1/fhir/Patient",
            params={"family": "Müller", "birthdate": "1980-05-17"},
            headers=professional,
        )
        search = events(AuditAction.PATIENT_SEARCHED)[-1]
        assert search.detail == {"matches": 2}
        recorded = json.dumps(search.detail, ensure_ascii=False)
        assert "Müller" not in recorded and "1980" not in recorded

    def test_a_single_match_records_which_patient(self, client, professional, patients):
        erika = patients["erika"]
        client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{LOCAL}|{erika.uid}"},
            headers=professional,
        )
        cross = events(AuditAction.PATIENT_CROSS_REFERENCED)[-1]
        assert cross.resource_uid == erika.uid

    def test_the_audit_chain_still_verifies(self, client, professional, patients, db):
        from ehealth.container import get_container  # noqa: F401

        client.get(
            "/v1/fhir/Patient",
            params={"family": "Müller", "birthdate": "1980-05-17"},
            headers=professional,
        )
        assert client.get("/v1/audit/verify").json()["ok"]


class TestServiceLimits:
    def test_too_many_matches_are_refused(
        self, container, db, patients, world, system_actor
    ):
        """A search that matches more than the limit is not a lookup of one
        person; the caller must narrow it rather than receive a list."""
        from ehealth.services.audit import ActorContext

        directory = PatientDirectory(
            container.persons,
            container.identity,
            container.ledger,
            community_oid=COMMUNITY,
            max_results=1,
        )
        doctor = ActorContext(actor_uid=world.doctor.uid, actor_kind="person")
        with pytest.raises(DirectoryError) as caught:
            directory.search(db, doctor, family="Müller", birthdate=date(1980, 5, 17))
        assert caught.value.code == "too-costly"


class TestNormalisation:
    @pytest.mark.parametrize(
        "spellings",
        [
            ("Müller", "Mueller", "MÜLLER", "müller"),
            ("von Allmen-Zürcher", "VON ALLMEN ZUERCHER", "vonallmenzuercher"),
            ("Rossé", "Rosse", "ROSSÉ"),
            ("Grüß", "Gruess"),
        ],
    )
    def test_spellings_of_one_name_meet(self, spellings):
        assert len({normalise_family_name(s) for s in spellings}) == 1

    def test_a_different_name_stays_different(self):
        """Stripping the umlaut would merge them; transliterating does not."""
        assert normalise_family_name("Müller") != normalise_family_name("Muller")


class TestReindex:
    def test_people_registered_without_the_index_are_filled_in(
        self, container, db, patients
    ):
        erika = db.get(Person, patients["erika"].uid)
        expected = erika.demographic_index
        erika.demographic_index = None
        db.flush()
        updated, _ = reindex(db, container.identity)
        assert updated == 1
        assert erika.demographic_index == expected

    def test_it_is_idempotent(self, container, db, patients):
        reindex(db, container.identity)
        assert reindex(db, container.identity)[0] == 0
