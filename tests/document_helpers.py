# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Shared helpers for the document and FHIR tests: a logged-in patient and
doctor, a capability for the patient's dossier, and an ITI-65 bundle."""

from __future__ import annotations

import base64

from ehealth.services.patient_directory import EPR_SPID_OID

SPID = f"urn:oid:{EPR_SPID_OID}"
SNOMED = "http://snomed.info/sct"
LEVEL = {"normal": "17621005", "restricted": "263856008", "secret": "1141000195107"}
LOINC_DISCHARGE = {"system": "http://loinc.org", "code": "18842-5"}
PDF = b"%PDF-1.7\n% discharge letter for Anna Muster\n"


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
