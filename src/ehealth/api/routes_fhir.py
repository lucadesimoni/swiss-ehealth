# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""FHIR R4 endpoints for patient identity: IHE PIXm (ITI-83), PDQm (ITI-78).

Shapes follow the CH EPR FHIR implementation guide (eHealth Suisse):

* ``GET /fhir/Patient/$ihe-pix?sourceIdentifier=urn:oid:…|…&targetSystem=…``
  returns a ``Parameters`` resource with one ``targetIdentifier`` per match
  and a ``targetId`` reference to the patient.
* ``GET /fhir/Patient?identifier=…`` or ``?family=…&birthdate=…[&given=…]
  [&gender=…]`` returns a ``searchset`` ``Bundle``.
* ``GET /fhir/Patient/{id}`` reads one patient by our local id.
* ``GET /fhir/metadata`` is the ``CapabilityStatement`` conformance tools ask
  for first.

Errors are ``OperationOutcome`` resources with the HTTP status the IHE
profile prescribes for each case (see ``services/patient_directory.py``).

What is *not* here, and a certified community needs: IUA (ITI-71/72) access
tokens, ATNA audit messages to a national audit repository, and the
document-exchange profiles (MHD). Access is by this system's own session
token for a healthcare professional.
"""

from __future__ import annotations

from datetime import date
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from ehealth.api.deps import ContainerDep, DbDep, DirectoryActorDep
from ehealth.services.patient_directory import (
    EPR_SPID_OID,
    OID_URN,
    DirectoryError,
    PatientRecord,
)
from ehealth.version import API_VERSION, __version__

router = APIRouter(prefix="/fhir", tags=["fhir"])

FHIR_JSON = "application/fhir+json"


def _fhir(body: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=FHIR_JSON)


def operation_outcome(error: DirectoryError) -> JSONResponse:
    return _fhir(
        {
            "resourceType": "OperationOutcome",
            "issue": [
                {
                    "severity": "error",
                    "code": error.code,
                    "diagnostics": error.diagnostics,
                }
            ],
        },
        error.status,
    )


def _base(request: Request) -> str:
    return f"{str(request.base_url).rstrip('/')}/{API_VERSION}/fhir"


def patient_resource(record: PatientRecord, community_oid: str) -> dict[str, Any]:
    """A Patient carrying exactly what the directory discloses.

    Both identifiers the CH EPR profile expects — the EPR-SPID and the local
    MPI-PID — and name, birth date, gender. No contact details, no AHVN13.
    """
    identifiers = [{"system": f"{OID_URN}{community_oid}", "value": record.uid}]
    if record.spid:
        identifiers.append({"system": f"{OID_URN}{EPR_SPID_OID}", "value": record.spid})
    resource: dict[str, Any] = {
        "resourceType": "Patient",
        "id": record.uid,
        "identifier": identifiers,
        "active": record.active,
        "gender": record.gender,
    }
    name: dict[str, Any] = {}
    if record.family_name:
        name["family"] = record.family_name
    if record.given_name:
        name["given"] = record.given_name.split()
    if name:
        resource["name"] = [name]
    if record.birth_date:
        resource["birthDate"] = record.birth_date.isoformat()
    return resource


def _parse_birthdate(raw: str | None) -> date | None:
    """FHIR date search: plain or ``eq``-prefixed ``YYYY-MM-DD`` only.

    Ranges (``ge``, ``lt`` …) are refused: a range search over birth dates is
    a listing, not a lookup of one person.
    """
    if raw is None:
        return None
    value = raw[2:] if raw.startswith("eq") else raw
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise DirectoryError(
            400, "code-invalid", "birthdate must be an exact date YYYY-MM-DD"
        ) from exc


@router.get("/metadata")
def capability_statement(request: Request, container: ContainerDep):
    """What this server supports, for conformance tooling. Public."""
    api = f"{str(request.base_url).rstrip('/')}/{API_VERSION}"
    return _fhir(
        {
            "resourceType": "CapabilityStatement",
            "status": "active",
            "kind": "instance",
            "fhirVersion": "4.0.1",
            "format": [FHIR_JSON],
            "software": {"name": "swiss-ehealth", "version": __version__},
            "implementationGuide": ["http://fhir.ch/ig/ch-epr-fhir"],
            "rest": [
                {
                    "mode": "server",
                    # IUA (ITI-72): every interaction below takes an IUA
                    # access token; the endpoints are in ITI-103 metadata.
                    "security": {
                        "service": [
                            {
                                "coding": [
                                    {
                                        "system": (
                                            "http://terminology.hl7.org/"
                                            "CodeSystem/restful-security-service"
                                        ),
                                        "code": "SMART-on-FHIR",
                                    }
                                ]
                            }
                        ],
                        "extension": [
                            {
                                "url": (
                                    "http://fhir-registry.smarthealthit.org/"
                                    "StructureDefinition/oauth-uris"
                                ),
                                "extension": [
                                    {
                                        "url": "authorize",
                                        "valueUri": f"{api}/iua/authorize",
                                    },
                                    {"url": "token", "valueUri": f"{api}/iua/token"},
                                ],
                            }
                        ],
                    },
                    "resource": [
                        {
                            "type": "Patient",
                            "interaction": [{"code": "read"}, {"code": "search-type"}],
                            "searchParam": [
                                {"name": "identifier", "type": "token"},
                                {"name": "family", "type": "string"},
                                {"name": "given", "type": "string"},
                                {"name": "birthdate", "type": "date"},
                                {"name": "gender", "type": "token"},
                            ],
                            "operation": [
                                {
                                    "name": "ihe-pix",
                                    "definition": (
                                        "http://profiles.ihe.net/ITI/PIXm/"
                                        "OperationDefinition/IHE.PIXm.pix"
                                    ),
                                },
                                {
                                    "name": "match",
                                    "definition": (
                                        "http://profiles.ihe.net/ITI/PDQm/"
                                        "OperationDefinition/PDQmMatch"
                                    ),
                                },
                            ],
                        }
                    ],
                }
            ],
        }
    )


@router.get("/Patient/$ihe-pix")
def pix_query(
    actor: DirectoryActorDep,
    db: DbDep,
    container: ContainerDep,
    sourceIdentifier: Annotated[str, Query(max_length=200)],
    targetSystem: Annotated[list[str] | None, Query()] = None,
):
    """ITI-83: the same patient's identifiers in other domains."""
    try:
        patient_uid, found = container.directory.cross_reference(
            db,
            actor,
            source_identifier=sourceIdentifier,
            target_systems=tuple(targetSystem or ()),
        )
    except DirectoryError as error:
        db.commit()  # the refusal is audited; keep that record
        return operation_outcome(error)
    parameters: list[dict[str, Any]] = [
        {
            "name": "targetIdentifier",
            "valueIdentifier": {"system": f"{OID_URN}{oid}", "value": value},
        }
        for oid, value in found
    ]
    if found:
        parameters.append(
            {
                "name": "targetId",
                "valueReference": {"reference": f"Patient/{patient_uid}"},
            }
        )
    return _fhir({"resourceType": "Parameters", "parameter": parameters})


@router.get("/Patient")
def pdq_search(
    request: Request,
    actor: DirectoryActorDep,
    db: DbDep,
    container: ContainerDep,
    identifier: Annotated[str | None, Query(max_length=200)] = None,
    family: Annotated[str | None, Query(max_length=100)] = None,
    given: Annotated[str | None, Query(max_length=100)] = None,
    birthdate: Annotated[str | None, Query(max_length=12)] = None,
    gender: Annotated[str | None, Query(max_length=10)] = None,
):
    """ITI-78: find a patient by identifier, or by family name and birth date."""
    try:
        records = container.directory.search(
            db,
            actor,
            identifier=identifier,
            family=family,
            given=given,
            birthdate=_parse_birthdate(birthdate),
            gender=gender,
        )
    except DirectoryError as error:
        db.commit()
        return operation_outcome(error)
    base = _base(request)
    community = container.directory.community_oid
    return _fhir(
        {
            "resourceType": "Bundle",
            "type": "searchset",
            "total": len(records),
            "entry": [
                {
                    "fullUrl": f"{base}/Patient/{record.uid}",
                    "resource": patient_resource(record, community),
                    "search": {"mode": "match"},
                }
                for record in records
            ],
        }
    )


MATCH_GRADE = "http://hl7.org/fhir/StructureDefinition/match-grade"


@router.post("/Patient/$match")
async def pdq_match(
    request: Request,
    actor: DirectoryActorDep,
    db: DbDep,
    container: ContainerDep,
):
    """ITI-119: score candidates for a Patient resource the caller posts.

    The form the CH EPR FHIR guide (v5) selects for patient identification.
    Input is a ``Parameters`` resource with ``resource`` (a Patient),
    optional ``onlyCertainMatches`` and ``count``.
    """
    try:
        body = await request.json()
    except ValueError:
        return operation_outcome(DirectoryError(400, "invalid", "body is not JSON"))
    if body.get("resourceType") != "Parameters":
        return operation_outcome(
            DirectoryError(400, "invalid", "$match expects a Parameters resource")
        )
    by_name = {p.get("name"): p for p in body.get("parameter") or []}
    patient = (by_name.get("resource") or {}).get("resource") or {}
    if patient.get("resourceType") != "Patient":
        return operation_outcome(
            DirectoryError(400, "required", "parameter 'resource' must hold a Patient")
        )
    only_certain = bool((by_name.get("onlyCertainMatches") or {}).get("valueBoolean"))
    count = (by_name.get("count") or {}).get("valueInteger")
    name = (patient.get("name") or [{}])[0]
    try:
        matches = container.directory.match(
            db,
            actor,
            identifiers=[
                f"{i.get('system', '')}|{i.get('value', '')}"
                for i in patient.get("identifier") or []
            ],
            family=name.get("family"),
            given=" ".join(name.get("given") or []) or None,
            birthdate=_parse_birthdate(patient.get("birthDate")),
            gender=patient.get("gender"),
            only_certain=only_certain,
            count=count if isinstance(count, int) and count > 0 else None,
        )
    except DirectoryError as error:
        db.commit()
        return operation_outcome(error)
    base = _base(request)
    community = container.directory.community_oid
    return _fhir(
        {
            "resourceType": "Bundle",
            "type": "searchset",
            "total": len(matches),
            "entry": [
                {
                    "fullUrl": f"{base}/Patient/{record.uid}",
                    "resource": patient_resource(record, community),
                    "search": {
                        "mode": "match",
                        "score": score,
                        "extension": [{"url": MATCH_GRADE, "valueCode": grade}],
                    },
                }
                for record, score, grade in matches
            ],
        }
    )


@router.get("/Patient/{patient_id}")
def pdq_read(
    patient_id: str,
    actor: DirectoryActorDep,
    db: DbDep,
    container: ContainerDep,
):
    try:
        record = container.directory.read(db, actor, patient_id)
    except DirectoryError as error:
        db.commit()
        return operation_outcome(error)
    return _fhir(patient_resource(record, container.directory.community_oid))
