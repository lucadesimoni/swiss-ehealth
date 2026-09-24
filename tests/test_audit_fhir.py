# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The patient's audit trail as FHIR AuditEvents (CH:ATC, EPDV art. 17)."""

from __future__ import annotations

from ehealth.services.patient_directory import EPR_SPID_OID
from tests.document_helpers import publish, published_uid

SPID = f"urn:oid:{EPR_SPID_OID}"


def trail(client, who, world, **params):
    return client.get(
        "/v1/fhir/AuditEvent",
        params={"patient.identifier": f"{SPID}|{world.patient.spid}", **params},
        headers=who.auth_header,
    )


class TestPatientTrail:
    def test_the_patient_sees_who_read_their_document(
        self, client, patient, headers, world
    ):
        uid = published_uid(publish(client, headers, world))
        client.get(f"/v1/fhir/Binary/{uid}", headers=headers)

        response = trail(client, patient, world)
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("application/fhir+json")
        events = [e["resource"] for e in response.json()["entry"]]
        codes = {e["subtype"][0]["code"] for e in events}
        assert {"ATC_DOC_CREATE", "ATC_DOC_READ"} <= codes

        (read,) = [e for e in events if e["subtype"][0]["code"] == "ATC_DOC_READ"]
        assert read["action"] == "R"
        assert read["outcome"] == "0"
        assert read["agent"][0]["who"]["identifier"]["value"] == world.doctor.uid
        assert read["agent"][0]["purposeOfUse"][0]["text"] == "treatment"
        assert read["entity"][0]["what"]["reference"] == f"Patient/{world.patient.uid}"
        assert any(
            e.get("what", {}).get("identifier", {}).get("value") == uid
            for e in read["entity"]
        )

    def test_every_event_carries_its_ledger_position(
        self, client, patient, headers, world
    ):
        publish(client, headers, world)
        (event, *_) = [
            e["resource"] for e in trail(client, patient, world).json()["entry"]
        ]
        tags = {t["system"].rpartition(":")[2]: t["code"] for t in event["meta"]["tag"]}
        assert int(tags["ledger-seq"]) >= 1
        assert len(tags["ledger-hash"]) >= 32

    def test_events_without_a_ch_atc_code_keep_their_own_name(
        self, client, patient, headers, world
    ):
        """Forcing a consent change onto a document code would be a lie."""
        events = [e["resource"] for e in trail(client, patient, world).json()["entry"]]
        local = [e for e in events if not e["subtype"][0]["code"].startswith("ATC_")]
        assert local
        assert all(
            e["subtype"][0]["system"].startswith("urn:ch:ehealth") for e in local
        )

    def test_a_date_filter_in_the_future_returns_nothing(
        self, client, patient, headers, world
    ):
        publish(client, headers, world)
        assert trail(client, patient, world, date="ge2999-01-01").json()["total"] == 0

    def test_nobody_else_may_read_the_trail(self, client, doctor, headers, world):
        """Not even the treating doctor: the trail is the patient's check on
        them."""
        response = trail(client, doctor, world)
        assert response.status_code == 403
        assert response.json()["resourceType"] == "OperationOutcome"

    def test_a_malformed_date_is_400(self, client, patient, world):
        assert trail(client, patient, world, date="yesterday").status_code == 400
