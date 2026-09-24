# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Dossier and document endpoints.

Every route below takes a capability token in ``X-Capability``; the session
token in ``Authorization`` identifies *who* is calling, the capability says
*what they may do to which dossier*.
"""

from __future__ import annotations

import base64
import binascii
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status

from ehealth.api.deps import (
    ContainerDep,
    CurrentUserDep,
    DbDep,
    capability_access,
)
from ehealth.api.routes_auth import AdminKeyDep
from ehealth.api.schemas import (
    DocumentCreate,
    DocumentOut,
    DossierCreate,
    DossierOut,
    RevokeIn,
)
from ehealth.security.tokens import Scope
from ehealth.services.access import AuthorizedAccess
from ehealth.services.audit import ActorContext
from ehealth.services.dossier import DocumentInput, DossierError
from ehealth.services.persons import PersonError

router = APIRouter(tags=["dossier"])

ReadAccess = Annotated[AuthorizedAccess, Depends(capability_access(Scope.DOSSIER_READ))]
WriteAccess = Annotated[
    AuthorizedAccess, Depends(capability_access(Scope.DOCUMENT_WRITE))
]
DocumentReadAccess = Annotated[
    AuthorizedAccess, Depends(capability_access(Scope.DOCUMENT_READ))
]

MAX_DOCUMENT_BYTES = 32 * 1024 * 1024


def _dossier_out(dossier) -> DossierOut:
    return DossierOut(
        uid=dossier.uid,
        patient_uid=dossier.patient_uid,
        status=dossier.status,
        opened_at=dossier.opened_at,
        retention_until=dossier.retention_until,
        default_confidentiality=dossier.default_confidentiality,
        home_community=dossier.home_community,
        version=dossier.version,
    )


def _document_out(document) -> DocumentOut:
    return DocumentOut(
        uid=document.uid,
        dossier_uid=document.dossier_uid,
        title=document.title,
        document_class=document.document_class,
        mime_type=document.mime_type,
        language=document.language,
        confidentiality=document.confidentiality,
        status=document.status,
        author_uid=document.author_uid,
        author_organization_uid=document.author_organization_uid,
        content_hash=document.content_hash,
        content_size=document.content_size,
        created_at=document.created_at,
        version=document.version,
    )


@router.post(
    "/dossiers",
    response_model=DossierOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def open_dossier(
    payload: DossierCreate,
    db: DbDep,
    container: ContainerDep,
):
    """Open a dossier for a registered patient. Enrolment-side operation."""
    try:
        patient = container.persons.get(db, payload.patient_uid)
        dossier = container.dossiers.open(
            db,
            ActorContext.system(),
            patient=patient,
            home_community=payload.home_community,
            default_confidentiality=payload.default_confidentiality,
        )
    except (DossierError, PersonError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _dossier_out(dossier)


@router.get("/dossiers/me", response_model=DossierOut)
def read_own_dossier(db: DbDep, container: ContainerDep, user: CurrentUserDep):
    dossier = container.dossiers.for_patient(db, user.claims.subject_uid)
    if dossier is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return _dossier_out(dossier)


@router.get("/dossiers/{dossier_uid}/documents", response_model=list[DocumentOut])
def list_documents(
    dossier_uid: Annotated[str, Path()],
    db: DbDep,
    container: ContainerDep,
    access: ReadAccess,
    include_superseded: Annotated[bool, Query()] = False,
):
    """Documents the caller's level reaches. Anything above it is invisible."""
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    documents = container.dossiers.list_documents(
        db, access, include_superseded=include_superseded
    )
    return [_document_out(document) for document in documents]


@router.post(
    "/dossiers/{dossier_uid}/documents",
    response_model=DocumentOut,
    status_code=status.HTTP_201_CREATED,
)
def add_document(
    dossier_uid: Annotated[str, Path()],
    payload: DocumentCreate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    access: WriteAccess,
):
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        content = base64.b64decode(payload.content_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="content_base64 is not valid base64",
        ) from exc
    if len(content) > MAX_DOCUMENT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="document exceeds the maximum size",
        )
    author = container.persons.get(db, user.claims.subject_uid)
    try:
        document = container.dossiers.add_document(
            db,
            access,
            author=author,
            document=DocumentInput(
                title=payload.title,
                document_class=payload.document_class,
                mime_type=payload.mime_type,
                content=content,
                confidentiality=payload.confidentiality,
                language=payload.language,
                supersedes_uid=payload.supersedes_uid,
                service_start=payload.service_start,
                service_end=payload.service_end,
            ),
        )
    except DossierError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _document_out(document)


@router.get(
    "/dossiers/{dossier_uid}/documents/{document_uid}", response_model=DocumentOut
)
def read_document(
    dossier_uid: Annotated[str, Path()],
    document_uid: Annotated[str, Path()],
    db: DbDep,
    container: ContainerDep,
    access: DocumentReadAccess,
):
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        document = container.dossiers.read_document(db, access, document_uid)
    except DossierError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return _document_out(document)


@router.get("/dossiers/{dossier_uid}/documents/{document_uid}/content")
def read_document_content(
    dossier_uid: Annotated[str, Path()],
    document_uid: Annotated[str, Path()],
    db: DbDep,
    container: ContainerDep,
    access: DocumentReadAccess,
):
    """The document's bytes, decrypted and checked against the stored hash."""
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        document, content = container.dossiers.read_content(db, access, document_uid)
    except DossierError as exc:
        db.commit()  # keep the audit record of a refused or failed read
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return Response(
        content=content,
        media_type=document.mime_type,
        headers={
            # Never let a browser guess a type for health data, and never let
            # an intermediary keep a copy.
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Disposition": "attachment",
            "Digest": f"sha-256={document.content_hash}",
        },
    )


@router.post(
    "/dossiers/{dossier_uid}/documents/{document_uid}/retract",
    response_model=DocumentOut,
)
def retract_document(
    dossier_uid: Annotated[str, Path()],
    document_uid: Annotated[str, Path()],
    payload: RevokeIn,
    db: DbDep,
    container: ContainerDep,
    access: WriteAccess,
):
    """Withdraw a document without deleting it."""
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        document = container.dossiers.retract_document(
            db, access, document_uid, reason=payload.reason
        )
    except DossierError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return _document_out(document)
