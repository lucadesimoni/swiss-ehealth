# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""IHE MHD over FHIR R4: publish, find and retrieve documents.

The document-sharing profile of the CH EPR FHIR guide, in its three core
transactions:

* **ITI-65 Provide Document Bundle** — ``POST /fhir`` with a ``transaction``
  Bundle holding a SubmissionSet ``List``, one or more ``DocumentReference``
  and the ``Binary`` each one points to.
* **ITI-67 Find Document References** — ``GET /fhir/DocumentReference?
  patient.identifier=urn:oid:…|…[&status=current]``.
* **ITI-68 Retrieve Document** — ``GET /fhir/Binary/{id}``, the URL each
  DocumentReference's attachment carries.

Authorisation is an **IUA extended access token** (ITI-72) in
``Authorization: Bearer``, as the guide requires, naming *that patient's*
EPR-SPID; see :mod:`ehealth.services.iua`. This system's own portal may
instead present a capability (``X-Capability``) with its session token. Either
way the confidentiality ceiling — from the patient's consent, evaluated at
the time of the request — filters what a search returns, in the query,
exactly as ``/dossiers/{uid}/documents`` does: a document above the caller's
level is neither returned nor counted.

Mapping to the internal model, deliberately explicit:

=====================================  =========================================
DocumentReference                       DossierDocument
=====================================  =========================================
``type.coding[0]`` system|code          ``document_class``
``securityLabel`` (SNOMED CT)           ``confidentiality``: 17621005 normal,
                                        263856008 restricted, 1141000195107
                                        secret — the CH EPR value set
``description``                         ``title``
``content.attachment.contentType``      ``mime_type``
``content.attachment.language``         ``language``
``relatesTo[replaces]``                 ``supersedes_uid``
``status``                              current / superseded; retracted is
                                        published as ``entered-in-error``
=====================================  =========================================

Not implemented: ITI-66 (find SubmissionSets) and metadata update
(ITI-105/106); see ``docs/interoperability.md``.
"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse

from ehealth.api.deps import (
    ContainerDep,
    DbDep,
    DocumentAccess,
    document_access,
)
from ehealth.api.routes_dossier import MAX_DOCUMENT_BYTES
from ehealth.api.routes_fhir import FHIR_JSON, operation_outcome
from ehealth.models.base import Confidentiality
from ehealth.models.clinical import Dossier, DossierDocument
from ehealth.security.tokens import Scope
from ehealth.services.dossier import DocumentInput, DossierError
from ehealth.services.patient_directory import (
    EPR_SPID_OID,
    OID_URN,
    DirectoryError,
)
from ehealth.version import API_VERSION

router = APIRouter(prefix="/fhir", tags=["fhir"])

SNOMED = "http://snomed.info/sct"
CONFIDENTIALITY_CODES: dict[Confidentiality, str] = {
    Confidentiality.NORMAL: "17621005",
    Confidentiality.RESTRICTED: "263856008",
    Confidentiality.SECRET: "1141000195107",
}
_CODE_TO_LEVEL = {code: level for level, code in CONFIDENTIALITY_CODES.items()}
_STATUS = {
    "current": "current",
    "superseded": "superseded",
    "retracted": "entered-in-error",
}

ReadAccess = Annotated[DocumentAccess, Depends(document_access(Scope.DOCUMENT_READ))]
WriteAccess = Annotated[DocumentAccess, Depends(document_access(Scope.DOCUMENT_WRITE))]


def _fhir(body: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=FHIR_JSON)


def _problem(status: int, code: str, diagnostics: str) -> JSONResponse:
    return operation_outcome(DirectoryError(status, code, diagnostics))


def _base(request: Request) -> str:
    return f"{str(request.base_url).rstrip('/')}/{API_VERSION}/fhir"


def _patient_dossier(db, container, access: DocumentAccess, identifier: str):
    """The dossier the identifier names — which must be the one the
    capability was issued for. A token for Anna's dossier cannot be pointed
    at Beat's by changing a query parameter."""
    patient = container.directory.resolve(db, identifier)
    if patient is None:
        return None
    dossier = container.dossiers.for_patient(db, patient.uid)
    if dossier is None or dossier.uid != access.dossier_uid:
        return None
    return patient, dossier


def document_reference(
    document: DossierDocument,
    *,
    patient_spid: str | None,
    patient_uid: str,
    community_oid: str,
    base: str,
) -> dict[str, Any]:
    system, _, code = document.document_class.rpartition("|")
    type_coding: dict[str, Any] = {"code": code or document.document_class}
    if system:
        type_coding["system"] = system
    subject_identifier = (
        {"system": f"{OID_URN}{EPR_SPID_OID}", "value": patient_spid}
        if patient_spid
        else {"system": f"{OID_URN}{community_oid}", "value": patient_uid}
    )
    resource: dict[str, Any] = {
        "resourceType": "DocumentReference",
        "id": document.uid,
        "masterIdentifier": {
            "system": "urn:ietf:rfc:3986",
            "value": f"urn:uid:{document.uid}",
        },
        "status": _STATUS.get(document.status, "current"),
        "type": {"coding": [type_coding]},
        "subject": {"identifier": subject_identifier},
        "date": document.created_at.isoformat() if document.created_at else None,
        "description": document.title,
        "securityLabel": [
            {
                "coding": [
                    {
                        "system": SNOMED,
                        "code": CONFIDENTIALITY_CODES[
                            Confidentiality(document.confidentiality)
                        ],
                    }
                ]
            }
        ],
        "content": [
            {
                "attachment": {
                    "contentType": document.mime_type,
                    "language": document.language,
                    "url": f"{base}/Binary/{document.uid}",
                    "size": document.content_size,
                    "title": document.title,
                }
            }
        ],
        "context": {},
    }
    if document.supersedes_uid:
        resource["relatesTo"] = [
            {
                "code": "replaces",
                "target": {"reference": f"DocumentReference/{document.supersedes_uid}"},
            }
        ]
    if document.service_start or document.service_end:
        resource["context"]["period"] = {
            key: value.isoformat()
            for key, value in (
                ("start", document.service_start),
                ("end", document.service_end),
            )
            if value
        }
    if not resource["context"]:
        del resource["context"]
    return resource


# -- ITI-67 ---------------------------------------------------------------------


@router.get("/DocumentReference")
def find_document_references(
    request: Request,
    db: DbDep,
    container: ContainerDep,
    access: ReadAccess,
    patient_identifier: Annotated[
        str, Query(alias="patient.identifier", max_length=200)
    ],
    status: Annotated[str | None, Query(max_length=20)] = None,
):
    try:
        resolved = _patient_dossier(db, container, access, patient_identifier)
    except DirectoryError as error:
        return operation_outcome(error)
    if resolved is None:
        # Unknown patient and "not the patient your token is for" look the
        # same: the profile answers an unknown patient with an empty result.
        return _fhir(
            {"resourceType": "Bundle", "type": "searchset", "total": 0, "entry": []}
        )
    patient, _ = resolved
    statuses = {s.strip() for s in status.split(",")} if status else {"current"}
    unknown = statuses - {"current", "superseded", "entered-in-error"}
    if unknown:
        return _problem(400, "code-invalid", f"unknown status {sorted(unknown)}")
    documents = container.dossiers.list_documents(
        db, access, include_superseded=statuses != {"current"}
    )
    base = _base(request)
    entries = [
        {
            "fullUrl": f"{base}/DocumentReference/{document.uid}",
            "resource": document_reference(
                document,
                patient_spid=patient.spid,
                patient_uid=patient.uid,
                community_oid=container.directory.community_oid,
                base=base,
            ),
            "search": {"mode": "match"},
        }
        for document in documents
        if _STATUS.get(document.status) in statuses
    ]
    return _fhir(
        {
            "resourceType": "Bundle",
            "type": "searchset",
            "total": len(entries),
            "entry": entries,
        }
    )


@router.get("/DocumentReference/{document_uid}")
def read_document_reference(
    document_uid: str,
    request: Request,
    db: DbDep,
    container: ContainerDep,
    access: ReadAccess,
):
    try:
        document = container.dossiers.read_document(db, access, document_uid)
    except DossierError:
        db.commit()
        return _problem(404, "not-found", "no such document")
    dossier = db.get(Dossier, document.dossier_uid)
    patient = container.persons.get(db, dossier.patient_uid)
    return _fhir(
        document_reference(
            document,
            patient_spid=patient.spid,
            patient_uid=patient.uid,
            community_oid=container.directory.community_oid,
            base=_base(request),
        )
    )


# -- ITI-68 ---------------------------------------------------------------------


@router.get("/Binary/{document_uid}")
def retrieve_document(
    document_uid: str,
    db: DbDep,
    container: ContainerDep,
    access: ReadAccess,
):
    try:
        document, content = container.dossiers.read_content(db, access, document_uid)
    except DossierError:
        db.commit()
        return _problem(404, "not-found", "no such document")
    return Response(
        content=content,
        media_type=document.mime_type,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Digest": f"sha-256={document.content_hash}",
        },
    )


# -- ITI-65 ---------------------------------------------------------------------


class _BundleError(Exception):
    def __init__(self, diagnostics: str, status: int = 400, code: str = "invalid"):
        super().__init__(diagnostics)
        self.status = status
        self.code = code


def _confidentiality(reference: dict) -> Confidentiality:
    for label in reference.get("securityLabel", []):
        for coding in label.get("coding", []):
            if coding.get("system") == SNOMED and coding.get("code") in _CODE_TO_LEVEL:
                return _CODE_TO_LEVEL[coding["code"]]
    # CH EPR requires a confidentiality code; a document without one is
    # refused rather than silently filed at the most visible level.
    raise _BundleError("DocumentReference needs a CH EPR confidentiality securityLabel")


def _document_class(reference: dict) -> str:
    codings = (reference.get("type") or {}).get("coding") or []
    if not codings or not codings[0].get("code"):
        raise _BundleError("DocumentReference needs type.coding with a code")
    coding = codings[0]
    return (
        f"{coding['system']}|{coding['code']}"
        if coding.get("system")
        else coding["code"]
    )


def _parse_bundle(bundle: dict) -> tuple[str, list[tuple[dict, bytes]]]:
    """Return (patient identifier, [(DocumentReference, content), …])."""
    if bundle.get("resourceType") != "Bundle" or bundle.get("type") != "transaction":
        raise _BundleError("ITI-65 expects a Bundle of type transaction")
    entries = bundle.get("entry") or []
    by_url = {e.get("fullUrl"): e.get("resource") or {} for e in entries}
    lists = [r for r in by_url.values() if r.get("resourceType") == "List"]
    references = [
        r for r in by_url.values() if r.get("resourceType") == "DocumentReference"
    ]
    if len(lists) != 1:
        raise _BundleError("ITI-65 expects exactly one SubmissionSet List")
    if not references:
        raise _BundleError("the bundle carries no DocumentReference")

    def subject(resource: dict) -> str:
        identifier = (resource.get("subject") or {}).get("identifier") or {}
        if not identifier.get("system") or not identifier.get("value"):
            raise _BundleError("subject must be given as an identifier (EPR-SPID)")
        return f"{identifier['system']}|{identifier['value']}"

    patient = subject(lists[0])
    documents: list[tuple[dict, bytes]] = []
    for reference in references:
        if subject(reference) != patient:
            raise _BundleError(
                "every document must be about the SubmissionSet's patient"
            )
        attachment = ((reference.get("content") or [{}])[0]).get("attachment") or {}
        binary = by_url.get(attachment.get("url"))
        if not binary or binary.get("resourceType") != "Binary":
            raise _BundleError("attachment.url must point at a Binary in the bundle")
        try:
            content = base64.b64decode(binary.get("data") or "", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _BundleError("Binary.data is not valid base64") from exc
        if not content:
            raise _BundleError("Binary.data is empty")
        if len(content) > MAX_DOCUMENT_BYTES:
            raise _BundleError("document exceeds the maximum size", 413, "too-costly")
        documents.append((reference, content))
    return patient, documents


@router.post("")
@router.post("/")
async def provide_document_bundle(
    request: Request,
    db: DbDep,
    container: ContainerDep,
    access: WriteAccess,
):
    try:
        bundle = await request.json()
    except ValueError:
        return _problem(400, "invalid", "body is not JSON")
    try:
        patient_identifier, documents = _parse_bundle(bundle)
        try:
            resolved = _patient_dossier(db, container, access, patient_identifier)
        except DirectoryError as error:
            raise _BundleError(error.diagnostics, error.status, error.code) from error
        if resolved is None:
            raise _BundleError(
                "the patient is unknown or not the one this capability is for",
                403,
                "forbidden",
            )
        author = container.persons.get(db, access.subject_uid)
        created: list[DossierDocument] = []
        for reference, content in documents:
            replaces = [
                r["target"]["reference"].rpartition("/")[2]
                for r in reference.get("relatesTo") or []
                if r.get("code") == "replaces"
                and (r.get("target") or {}).get("reference")
            ]
            attachment = reference["content"][0]["attachment"]
            created.append(
                container.dossiers.add_document(
                    db,
                    access,
                    author=author,
                    document=DocumentInput(
                        title=(
                            reference.get("description")
                            or attachment.get("title")
                            or "Untitled document"
                        )[:300],
                        document_class=_document_class(reference),
                        mime_type=attachment.get("contentType")
                        or "application/octet-stream",
                        content=content,
                        confidentiality=_confidentiality(reference),
                        language=attachment.get("language") or "de-CH",
                        supersedes_uid=replaces[0] if replaces else None,
                    ),
                )
            )
    except _BundleError as error:
        db.rollback()
        return _problem(error.status, error.code, str(error))
    except DossierError as error:
        db.rollback()
        return _problem(422, "processing", str(error))
    base = _base(request)
    return _fhir(
        {
            "resourceType": "Bundle",
            "type": "transaction-response",
            "entry": [
                {
                    "response": {
                        "status": "201 Created",
                        "location": f"{base}/DocumentReference/{document.uid}",
                    }
                }
                for document in created
            ],
        },
        200,
    )
