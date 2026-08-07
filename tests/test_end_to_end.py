# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""One full journey over HTTP, the way a real deployment would be driven.

Enrolment → patient login → consent → grant to a doctor → the doctor writes a
prescription → a visitor gets time-boxed read access → the patient reads their
own audit trail → the ledger verifies.
"""

from __future__ import annotations

import base64

import pytest

from ehealth.main import SECURITY_HEADERS

from tests.conftest import AHVN_ANNA, AHVN_BEAT, AHVN_CARLA, login


@pytest.fixture
def registry(client):
    """Enrolment-side setup, done with the admin key."""
    organization = client.post(
        "/organizations",
        json={"name": "Kantonsspital Test", "che_uid": "CHE-109.322.551"},
    )
    assert organization.status_code == 201, organization.text
    org_uid = organization.json()["uid"]

    patient = client.post(
        "/persons",
        json={
            "roles": ["patient"],
            "given_name": "Anna",
            "family_name": "Muster",
            "ahvn13": AHVN_ANNA,
            "birth_date": "1985-04-12",
            "email": "anna.muster@example.ch",
        },
    )
    assert patient.status_code == 201, patient.text

    doctor = client.post(
        "/persons",
        json={
            # Beat is registered as a patient too — one person, two roles.
            "roles": ["patient"],
            "given_name": "Beat",
            "family_name": "Arzt",
            "ahvn13": AHVN_BEAT,
        },
    )
    assert doctor.status_code == 201, doctor.text
    credential = client.post(
        f"/persons/{doctor.json()['uid']}/credentials",
        json={
            "gln": "7601000000002",
            "professional_register": "medreg",
            "profession": "physician",
            "specialisation": "Facharzt Allgemeine Innere Medizin",
            "licence_canton": "ZH",
            "licence_number": "ZH-2019-04412",
            "zsr_number": "A123456",
            "organization_uid": org_uid,
        },
    )
    assert credential.status_code == 201, credential.text
    verified = client.post(
        f"/credentials/{credential.json()['uid']}/verify",
        json={"source": "MedReg", "evidence": {"checked": "e2e"}},
    )
    assert verified.status_code == 200, verified.text

    visitor = client.post(
        "/persons",
        json={
            "roles": ["visitor"],
            "given_name": "Carla",
            "family_name": "Besuch",
            "ahvn13": AHVN_CARLA,
        },
    )
    assert visitor.status_code == 201, visitor.text

    dossier = client.post(
        "/dossiers", json={"patient_uid": patient.json()["uid"]}
    )
    assert dossier.status_code == 201, dossier.text

    product = client.post(
        "/products",
        json={
            "gtin": "7601000000002",
            "name": "Lisinopril Test 10mg",
            "atc_code": "C09AA03",
            "active_ingredient": "Lisinopril",
            "strength": "10 mg",
            "swissmedic_authorisation": "62536",
            "pharmacode": "1234567",
            "dispensing_category": "B",
            "sl_listed": True,
        },
    )
    assert product.status_code == 201, product.text

    return {
        "org": org_uid,
        "patient": patient.json(),
        "doctor": doctor.json(),
        "visitor": visitor.json(),
        "credential": verified.json(),
        "dossier": dossier.json(),
        "product": product.json(),
    }


class TestRegistration:
    def test_the_response_carries_an_18_digit_spid_not_the_ahv_number(self, registry):
        patient = registry["patient"]
        assert patient["uid"].startswith("per_")
        assert patient["spid"].startswith("761")
        assert len(patient["spid"]) == 18
        assert AHVN_ANNA not in str(patient)
        assert AHVN_ANNA.replace(".", "") not in str(patient)

    def test_a_person_can_hold_several_roles(self, client, registry):
        """The doctor is registered as a patient and holds a credential, so
        both roles are live on one record."""
        roles = client.get(f"/persons/{registry['doctor']['uid']}/roles").json()
        assert {r["role"] for r in roles if r["status"] == "active"} == {
            "patient",
            "healthcare_professional",
        }

    def test_the_credential_carries_swiss_registration(self, registry):
        credential = registry["credential"]
        assert credential["gln"] == "7601000000002"
        assert credential["professional_register"] == "medreg"
        assert credential["licence_canton"] == "ZH"
        assert credential["zsr_number"] == "A123456"
        assert credential["verified_at"] is not None
        assert credential["may_prescribe"] is True

    def test_a_duplicate_registration_is_a_conflict(self, client, registry):
        response = client.post(
            "/persons",
            json={
                "roles": ["patient"],
                "given_name": "Anna",
                "family_name": "Muster-Zweitversuch",
                "ahvn13": AHVN_ANNA,
            },
        )
        assert response.status_code == 409
        assert response.json()["detail"]["person_uid"] == registry["patient"]["uid"]

    def test_an_invalid_ahv_number_is_rejected_before_anything_happens(self, client):
        response = client.post(
            "/persons",
            json={
                "roles": ["patient"],
                "given_name": "Falsch",
                "family_name": "Nummer",
                "ahvn13": "756.1234.5678.98",
            },
        )
        assert response.status_code == 422

    def test_lookup_by_ahv_number_resolves_the_uid(self, client, registry):
        response = client.post("/persons/lookup", json={"ahvn13": AHVN_ANNA})
        assert response.status_code == 200
        assert response.json()["uid"] == registry["patient"]["uid"]

    def test_lookup_by_sector_id_resolves_the_same_person(self, client, registry):
        response = client.post(
            "/persons/lookup", json={"spid": registry["patient"]["spid"]}
        )
        assert response.json()["uid"] == registry["patient"]["uid"]

    def test_the_registry_is_closed_without_the_admin_key(self, client):
        response = client.post(
            "/persons",
            headers={"X-Admin-Key": "nope"},
            json={"roles": ["patient"], "given_name": "X", "family_name": "Y"},
        )
        assert response.status_code == 401


class TestFullJourney:
    def test_patient_grants_a_doctor_who_then_prescribes(
        self, client, mock_idp, outbox, registry
    ):
        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )

        # 1. The patient joins and sets their policy.
        consent = client.post(
            "/consent",
            headers=patient.auth_header,
            json={"default_access_level": "normal", "emergency_access_allowed": True},
        )
        assert consent.status_code == 201, consent.text

        # 2. The patient grants the doctor bounded access.
        grant = client.post(
            "/grants",
            headers=patient.auth_header,
            json={
                "dossier_uid": registry["dossier"]["uid"],
                "grantee_uid": registry["doctor"]["uid"],
                "purpose": "treatment",
                "scopes": [
                    "dossier:read",
                    "document:read",
                    "document:write",
                    "medication:read",
                    "medication:write",
                ],
                "ttl_seconds": 3600,
            },
        )
        assert grant.status_code == 201, grant.text
        grant_uid = grant.json()["uid"]

        # 3. The doctor logs in and exchanges the grant for a capability.
        doctor = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["doctor"]["uid"],
            subject="swissid-beat",
            email="beat.arzt@example.ch",
        )
        capability = client.post(
            f"/grants/{grant_uid}/token", headers=doctor.auth_header, json={}
        )
        assert capability.status_code == 200, capability.text
        cap_headers = {
            **doctor.auth_header,
            "X-Capability": capability.json()["token"],
        }

        # 4. The doctor prescribes.
        dossier_uid = registry["dossier"]["uid"]
        prescription = client.post(
            f"/dossiers/{dossier_uid}/medications",
            headers=cap_headers,
            json={
                "kind": "prescription",
                "product_uid": registry["product"]["uid"],
                "dosage": {"amount": 1, "unit": "tablet", "frequency": "1-0-0-0"},
                "reason": "Hypertonie",
            },
        )
        assert prescription.status_code == 201, prescription.text

        # 5. And files a consultation note.
        document = client.post(
            f"/dossiers/{dossier_uid}/documents",
            headers=cap_headers,
            json={
                "title": "Konsultation 2026-08-07",
                "document_class": "clinical-note",
                "mime_type": "text/plain",
                "content_base64": base64.b64encode(b"Blutdruck 150/95").decode(),
            },
        )
        assert document.status_code == 201, document.text

        # 6. The reconciled list shows the prescription.
        reconciled = client.get(
            f"/dossiers/{dossier_uid}/medications/reconciled", headers=cap_headers
        )
        assert reconciled.status_code == 200
        assert len(reconciled.json()) == 1
        assert reconciled.json()[0]["kind"] == "prescription"

        # 7. The patient sees who touched their record.
        trail = client.get("/audit/me", headers=patient.auth_header)
        assert trail.status_code == 200
        actions = {event["action"] for event in trail.json()}
        assert {"medication.added", "document.added", "grant.issued"} <= actions
        # Nobody but the doctor, the patient and the enrolment job appears.
        assert {event["actor_uid"] for event in trail.json()} <= {
            registry["doctor"]["uid"],
            registry["patient"]["uid"],
            None,
        }

        # 8. Revoking the grant closes the door immediately.
        revoked = client.post(
            f"/grants/{grant_uid}/revoke",
            headers=patient.auth_header,
            json={"reason": "Behandlung abgeschlossen"},
        )
        assert revoked.status_code == 200
        after = client.get(
            f"/dossiers/{dossier_uid}/medications/reconciled", headers=cap_headers
        )
        assert after.status_code == 403

        # 9. The ledger still verifies end to end.
        verification = client.get("/audit/verify")
        assert verification.status_code == 200
        assert verification.json()["ok"] is True
        assert verification.json()["checked"] > 10


class TestVisitorAccess:
    def test_a_visitor_gets_read_only_time_boxed_access(
        self, client, mock_idp, outbox, registry
    ):
        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        client.post("/consent", headers=patient.auth_header, json={})

        grant = client.post(
            "/grants/visitor",
            headers=patient.auth_header,
            json={
                "visitor_uid": registry["visitor"]["uid"],
                "scopes": ["dossier:read", "medication:read", "document:write"],
                "ttl_seconds": 3600,
                "max_uses": 5,
            },
        )
        assert grant.status_code == 201, grant.text
        # The write scope was asked for and silently dropped.
        assert "document:write" not in grant.json()["scopes"]
        assert grant.json()["grantee_kind"] == "visitor"

        visitor = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["visitor"]["uid"],
            subject="swissid-carla",
            email="carla.besuch@example.ch",
        )
        capability = client.post(
            f"/grants/{grant.json()['uid']}/token",
            headers=visitor.auth_header,
            json={},
        )
        assert capability.status_code == 200
        cap_headers = {
            **visitor.auth_header,
            "X-Capability": capability.json()["token"],
        }

        dossier_uid = registry["dossier"]["uid"]
        assert (
            client.get(
                f"/dossiers/{dossier_uid}/documents", headers=cap_headers
            ).status_code
            == 200
        )
        # Reading is allowed; writing is not, because the scope is not there.
        write = client.post(
            f"/dossiers/{dossier_uid}/documents",
            headers=cap_headers,
            json={
                "title": "should not exist",
                "document_class": "note",
                "content_base64": base64.b64encode(b"x").decode(),
            },
        )
        assert write.status_code == 403

    def test_a_visitor_cannot_grant_themselves_access(
        self, client, mock_idp, outbox, registry
    ):
        visitor = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["visitor"]["uid"],
            subject="swissid-carla",
            email="carla.besuch@example.ch",
        )
        response = client.post(
            "/grants/visitor",
            headers=visitor.auth_header,
            json={"visitor_uid": registry["visitor"]["uid"]},
        )
        assert response.status_code in (403, 404)


class TestEmergency:
    def test_break_glass_works_and_is_loudly_recorded(
        self, client, mock_idp, outbox, registry
    ):
        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        client.post("/consent", headers=patient.auth_header, json={})

        doctor = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["doctor"]["uid"],
            subject="swissid-beat",
            email="beat.arzt@example.ch",
        )
        response = client.post(
            "/access/emergency",
            headers=doctor.auth_header,
            json={
                "patient_uid": registry["patient"]["uid"],
                "justification": "Bewusstlose Patientin, Notfallstation",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["access_level"] == "restricted"

        cap_headers = {**doctor.auth_header, "X-Capability": response.json()["token"]}
        dossier_uid = registry["dossier"]["uid"]
        assert (
            client.get(
                f"/dossiers/{dossier_uid}/documents", headers=cap_headers
            ).status_code
            == 200
        )

        trail = client.get("/audit/me", headers=patient.auth_header)
        assert any(
            event["action"] == "access.emergency" for event in trail.json()
        )

    def test_a_patient_cannot_invoke_emergency_access(
        self, client, mock_idp, outbox, registry
    ):
        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        response = client.post(
            "/access/emergency",
            headers=patient.auth_header,
            json={
                "patient_uid": registry["patient"]["uid"],
                "justification": "just curious about this endpoint",
            },
        )
        assert response.status_code == 403


class TestPatientSelfAccess:
    def test_a_patient_reads_their_own_record_at_every_level(
        self, client, mock_idp, outbox, registry
    ):
        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        client.post("/consent", headers=patient.auth_header, json={})
        capability = client.post("/access/self", headers=patient.auth_header)
        assert capability.status_code == 200, capability.text
        assert capability.json()["access_level"] == "secret"

        cap_headers = {**patient.auth_header, "X-Capability": capability.json()["token"]}
        dossier_uid = registry["dossier"]["uid"]
        secret = client.post(
            f"/dossiers/{dossier_uid}/documents",
            headers=cap_headers,
            json={
                "title": "Nur für mich",
                "document_class": "patient-note",
                "mime_type": "text/plain",
                "content_base64": base64.b64encode(b"privat").decode(),
                "confidentiality": "secret",
            },
        )
        assert secret.status_code == 201
        listed = client.get(
            f"/dossiers/{dossier_uid}/documents", headers=cap_headers
        )
        assert len(listed.json()) == 1

    def test_contact_changes_are_versioned(self, client, mock_idp, outbox, registry):
        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        before = client.get("/persons/me", headers=patient.auth_header).json()
        updated = client.patch(
            "/persons/me/contact",
            headers=patient.auth_header,
            json={"phone": "+41 79 123 45 67", "reason": "neue Nummer"},
        )
        assert updated.status_code == 200
        assert updated.json()["version"] == before["version"] + 1
        assert updated.json()["phone"] == "+41 79 123 45 67"

        history = client.get(f"/history/person/{patient.person_uid}")
        assert history.status_code == 200
        assert [r["version"] for r in history.json()] == [1, 2]
        assert history.json()[1]["reason"] == "neue Nummer"


class TestTransportHardening:
    def test_security_headers_are_present(self, client):
        response = client.get("/health")
        for header in SECURITY_HEADERS:
            assert header in response.headers, header
        assert response.headers["X-Request-Id"]

    def test_the_request_id_is_echoed(self, client):
        response = client.get("/health", headers={"X-Request-Id": "abc-123"})
        assert response.headers["X-Request-Id"] == "abc-123"

    def test_unknown_fields_are_rejected(self, client, registry):
        response = client.post(
            "/persons",
            json={
                "roles": ["patient"],
                "given_name": "A",
                "family_name": "B",
                "ahvn13": "756.1111.1111.13",
                "unexpected_field": "silently ignored?",
            },
        )
        assert response.status_code == 422


class TestLedgerAnchoring:
    def test_anchors_and_reverifies(self, client, registry):
        anchor = client.post("/audit/anchor", params={"period": "2026-08-07"})
        assert anchor.status_code == 200, anchor.text
        body = anchor.json()
        assert body["event_count"] > 0
        assert len(body["head_hash"]) == 64

        again = client.post("/audit/anchor", params={"period": "2026-08-07"})
        assert again.json()["head_hash"] == body["head_hash"]

        assert client.get("/audit/verify").json()["ok"] is True
