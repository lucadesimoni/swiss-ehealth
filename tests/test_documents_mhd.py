# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Document storage and IHE MHD (ITI-65 publish, ITI-67 find, ITI-68 get).

Storage is tested as untrusted: what reaches it must be ciphertext, and what
comes back must be exactly what was written or the read fails.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from ehealth.security.crypto import KeyRing
from ehealth.services.blobstore import (
    BlobError,
    DocumentContentStore,
    FileSystemBlobStore,
    MemoryBlobStore,
)
from ehealth.services.patient_directory import EPR_SPID_OID
from tests.conftest import login

SPID = f"urn:oid:{EPR_SPID_OID}"
SNOMED = "http://snomed.info/sct"
LEVEL = {"normal": "17621005", "restricted": "263856008", "secret": "1141000195107"}
LOINC_DISCHARGE = {"system": "http://loinc.org", "code": "18842-5"}
PDF = b"%PDF-1.7\n% discharge letter for Anna Muster\n"


# -- fixtures -------------------------------------------------------------------


@pytest.fixture
def patient(client, mock_idp, outbox, world):
    return login(
        client,
        mock_idp,
        outbox,
        person_uid=world.patient.uid,
        subject="anna-swissid",
        email="anna.muster@example.ch",
    )


@pytest.fixture
def doctor(client, mock_idp, outbox, world):
    return login(
        client,
        mock_idp,
        outbox,
        person_uid=world.doctor.uid,
        subject="beat-swissid",
        email="beat.arzt@example.ch",
    )


def capability(client, patient, doctor, world, *, level="normal", scopes=None):
    grant = client.post(
        "/v1/grants",
        headers=patient.auth_header,
        json={
            "dossier_uid": world.dossier.uid,
            "grantee_uid": world.doctor.uid,
            "purpose": "treatment",
            "scopes": scopes or ["dossier:read", "document:read", "document:write"],
            "ttl_seconds": 3600,
            "access_level": level,
        },
    )
    assert grant.status_code == 201, grant.text
    token = client.post(
        f"/v1/grants/{grant.json()['uid']}/token", headers=doctor.auth_header, json={}
    )
    assert token.status_code == 200, token.text
    return {**doctor.auth_header, "X-Capability": token.json()["token"]}


@pytest.fixture
def headers(client, patient, doctor, world):
    """A doctor the patient has designated for RESTRICTED material (EPDV
    annex 2): the grant alone cannot raise the level, the consent rule does."""
    rule = client.post(
        "/v1/consent/rules",
        headers=patient.auth_header,
        json={
            "subject_type": "person",
            "subject_uid": world.doctor.uid,
            "effect": "allow",
            "access_level": "restricted",
        },
    )
    assert rule.status_code == 201, rule.text
    return capability(client, patient, doctor, world, level="restricted")


def bundle(
    spid, *, content=PDF, level="normal", title="Austrittsbericht", replaces=None
):
    subject = {"identifier": {"system": SPID, "value": spid}}
    reference = {
        "resourceType": "DocumentReference",
        "status": "current",
        "type": {"coding": [LOINC_DISCHARGE]},
        "subject": subject,
        "description": title,
        "securityLabel": [{"coding": [{"system": SNOMED, "code": LEVEL[level]}]}],
        "content": [
            {
                "attachment": {
                    "contentType": "application/pdf",
                    "language": "de-CH",
                    "url": "urn:uuid:binary-1",
                }
            }
        ],
    }
    if replaces:
        reference["relatesTo"] = [
            {
                "code": "replaces",
                "target": {"reference": f"DocumentReference/{replaces}"},
            }
        ]
    return {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "fullUrl": "urn:uuid:submission-set",
                "resource": {
                    "resourceType": "List",
                    "status": "current",
                    "mode": "working",
                    "subject": subject,
                },
            },
            {"fullUrl": "urn:uuid:docref-1", "resource": reference},
            {
                "fullUrl": "urn:uuid:binary-1",
                "resource": {
                    "resourceType": "Binary",
                    "contentType": "application/pdf",
                    "data": base64.b64encode(content).decode(),
                },
            },
        ],
    }


def publish(client, headers, world, **kwargs):
    response = client.post(
        "/v1/fhir", json=bundle(world.patient.spid, **kwargs), headers=headers
    )
    return response


def published_uid(response) -> str:
    (entry,) = response.json()["entry"]
    return entry["response"]["location"].rpartition("/")[2]


# -- storage ---------------------------------------------------------------------


class TestContentStore:
    @pytest.fixture
    def store(self):
        backend = MemoryBlobStore()
        return backend, DocumentContentStore(backend, KeyRing(b"k" * 32))

    def test_the_backend_only_ever_sees_ciphertext(self, store):
        backend, content = store
        content.store("doc_01ABCDEFGHJK", PDF)
        stored = backend.blobs["doc_01ABCDEFGHJK"]
        assert PDF not in stored and b"Anna" not in stored

    def test_round_trip(self, store):
        _, content = store
        content.store("doc_01ABCDEFGHJK", PDF)
        digest = hashlib.sha256(PDF).hexdigest()
        assert content.load("doc_01ABCDEFGHJK", expected_sha256=digest) == PDF

    def test_a_blob_moved_to_another_document_does_not_decrypt(self, store):
        """The ciphertext is bound to its document uid."""
        backend, content = store
        content.store("doc_01ABCDEFGHJK", PDF)
        backend.blobs["doc_01ZZZZZZZZZZ"] = backend.blobs["doc_01ABCDEFGHJK"]
        with pytest.raises(BlobError, match="does not decrypt"):
            content.load(
                "doc_01ZZZZZZZZZZ", expected_sha256=hashlib.sha256(PDF).hexdigest()
            )

    def test_content_that_differs_from_the_recorded_hash_is_refused(self, store):
        _, content = store
        content.store("doc_01ABCDEFGHJK", PDF)
        with pytest.raises(BlobError, match="recorded hash"):
            content.load("doc_01ABCDEFGHJK", expected_sha256="0" * 64)

    def test_filesystem_blobs_are_immutable_and_confined(self, tmp_path):
        backend = FileSystemBlobStore(tmp_path)
        backend.put("doc_01ABCDEFGHJK", b"x")
        with pytest.raises(BlobError, match="immutable"):
            backend.put("doc_01ABCDEFGHJK", b"y")
        with pytest.raises(BlobError, match="invalid content key"):
            backend.put("../../etc/passwd", b"x")
        assert backend.get("doc_01ABCDEFGHJK") == b"x"
        assert not list(tmp_path.rglob("*.partial"))


# -- ITI-65 ----------------------------------------------------------------------


class TestPublish:
    def test_a_document_is_published_and_readable(self, client, headers, world):
        response = publish(client, headers, world)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["type"] == "transaction-response"
        uid = published_uid(response)

        content = client.get(f"/v1/fhir/Binary/{uid}", headers=headers)
        assert content.status_code == 200
        assert content.content == PDF
        assert content.headers["content-type"] == "application/pdf"
        assert content.headers["cache-control"] == "no-store"
        assert content.headers["digest"] == f"sha-256={hashlib.sha256(PDF).hexdigest()}"

    def test_the_same_bytes_come_back_through_the_plain_api(
        self, client, headers, world
    ):
        uid = published_uid(publish(client, headers, world))
        response = client.get(
            f"/v1/dossiers/{world.dossier.uid}/documents/{uid}/content", headers=headers
        )
        assert response.content == PDF

    def test_publishing_needs_the_write_scope(self, client, patient, doctor, world):
        read_only = capability(
            client, patient, doctor, world, scopes=["dossier:read", "document:read"]
        )
        assert publish(client, read_only, world).status_code == 403

    def test_a_token_for_one_patient_cannot_file_for_another(
        self, client, headers, world
    ):
        foreign = bundle("761000000000000009")
        response = client.post("/v1/fhir", json=foreign, headers=headers)
        assert response.status_code in (400, 403)

    def test_a_document_without_a_confidentiality_code_is_refused(
        self, client, headers, world
    ):
        """Filing it at the most visible level by default would be the
        wrong kind of helpful."""
        payload = bundle(world.patient.spid)
        payload["entry"][1]["resource"]["securityLabel"] = []
        response = client.post("/v1/fhir", json=payload, headers=headers)
        assert response.status_code == 400
        assert "confidentiality" in response.json()["issue"][0]["diagnostics"]

    @pytest.mark.parametrize(
        ("mutate", "message"),
        [
            (lambda b: b.update(type="batch"), "transaction"),
            (lambda b: b["entry"].pop(0), "SubmissionSet"),
            (lambda b: b["entry"].pop(2), "Binary"),
            (
                lambda b: b["entry"][2]["resource"].update(data="%%%"),
                "base64",
            ),
            (
                lambda b: b["entry"][1]["resource"]["type"].update(coding=[]),
                "type.coding",
            ),
        ],
    )
    def test_malformed_bundles_are_refused_and_nothing_is_stored(
        self, client, headers, world, mutate, message
    ):
        payload = bundle(world.patient.spid)
        mutate(payload)
        response = client.post("/v1/fhir", json=payload, headers=headers)
        assert response.status_code == 400
        assert message in response.json()["issue"][0]["diagnostics"]
        found = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=headers,
        )
        assert found.json()["total"] == 0

    def test_a_replacement_supersedes_the_original(self, client, headers, world):
        first = published_uid(publish(client, headers, world))
        second = published_uid(
            publish(client, headers, world, content=PDF + b"v2", replaces=first)
        )
        current = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=headers,
        ).json()
        assert [e["resource"]["id"] for e in current["entry"]] == [second]
        both = client.get(
            "/v1/fhir/DocumentReference",
            params={
                "patient.identifier": f"{SPID}|{world.patient.spid}",
                "status": "current,superseded",
            },
            headers=headers,
        ).json()
        statuses = {e["resource"]["id"]: e["resource"]["status"] for e in both["entry"]}
        assert statuses == {first: "superseded", second: "current"}


# -- ITI-67 / ITI-68 -------------------------------------------------------------


class TestFindAndRetrieve:
    def test_the_document_reference_carries_the_ch_epr_metadata(
        self, client, headers, world
    ):
        uid = published_uid(publish(client, headers, world, level="restricted"))
        body = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=headers,
        ).json()
        (entry,) = body["entry"]
        reference = entry["resource"]
        assert reference["id"] == uid
        assert reference["subject"]["identifier"] == {
            "system": SPID,
            "value": world.patient.spid,
        }
        assert reference["type"]["coding"] == [LOINC_DISCHARGE]
        assert reference["securityLabel"][0]["coding"][0]["code"] == LEVEL["restricted"]
        attachment = reference["content"][0]["attachment"]
        assert attachment["url"].endswith(f"/v1/fhir/Binary/{uid}")
        assert attachment["size"] == len(PDF)

    def test_a_document_above_the_grant_is_invisible(
        self, client, patient, doctor, world, headers
    ):
        """Published at RESTRICTED; a NORMAL grant neither sees nor counts it,
        and cannot fetch it by id."""
        uid = published_uid(publish(client, headers, world, level="restricted"))
        normal = capability(client, patient, doctor, world, level="normal")
        body = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=normal,
        ).json()
        assert body["total"] == 0
        assert client.get(f"/v1/fhir/Binary/{uid}", headers=normal).status_code == 404
        assert (
            client.get(f"/v1/fhir/DocumentReference/{uid}", headers=normal).status_code
            == 404
        )

    def test_searching_another_patient_returns_nothing(self, client, headers, world):
        publish(client, headers, world)
        body = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|761000000000000009"},
            headers=headers,
        ).json()
        assert body["total"] == 0

    def test_without_a_capability_there_is_nothing(self, client, doctor, world):
        response = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=doctor.auth_header,
        )
        assert response.status_code == 401

    def test_tampered_storage_is_detected_on_read(
        self, client, headers, world, container
    ):
        uid = published_uid(publish(client, headers, world))
        backend = container.dossiers._content._backend
        stolen = backend.blobs[uid]
        other = published_uid(publish(client, headers, world, content=b"other"))
        backend.blobs[other] = stolen  # serve Anna's letter under another id
        response = client.get(f"/v1/fhir/Binary/{other}", headers=headers)
        assert response.status_code == 404
        assert b"%PDF" not in response.content

    def test_reads_are_audited(self, client, headers, world):
        uid = published_uid(publish(client, headers, world))
        client.get(f"/v1/fhir/Binary/{uid}", headers=headers)
        assert client.get("/v1/audit/verify").json()["ok"]
