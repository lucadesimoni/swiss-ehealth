# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Person and institution registry."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, status

from ehealth.api.deps import ContainerDep, CurrentUserDep, DbDep, RequestContextDep
from ehealth.api.routes_auth import AdminKeyDep
from ehealth.api.schemas import (
    ContactUpdate,
    CredentialCreate,
    CredentialOut,
    CredentialVerify,
    OrganizationCreate,
    OrganizationOut,
    PersonCreate,
    PersonLookup,
    PersonOut,
    RoleGrant,
    RoleOut,
)
from ehealth.domain.uid import CheUid, IdentifierError
from ehealth.models.core import PersonRoleKind
from ehealth.security.tokens import Scope
from ehealth.services.persons import (
    CredentialRegistration,
    DuplicatePersonError,
    PersonError,
    PersonRegistration,
)

router = APIRouter(tags=["registry"])


def _to_out(container, db, person) -> PersonOut:
    view = container.persons.view(db, person)
    return PersonOut(**asdict(view))


def _credential_out(container, db, credential) -> CredentialOut:
    from ehealth.db import utcnow

    return CredentialOut(
        uid=credential.uid,
        person_uid=credential.person_uid,
        gln=credential.gln,
        professional_register=credential.register,
        profession=credential.profession,
        specialisation=credential.specialisation,
        licence_canton=credential.licence_canton,
        licence_number=credential.licence_number,
        licence_valid_from=credential.licence_valid_from,
        licence_valid_until=credential.licence_valid_until,
        licence_suspended=credential.licence_suspended,
        zsr_number=credential.zsr_number,
        organization_uid=credential.organization_uid,
        verified_at=credential.verified_at,
        verification_source=credential.verification_source,
        may_prescribe=credential.may_prescribe(utcnow().date()),
        version=credential.version,
    )


@router.post(
    "/organizations",
    response_model=OrganizationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def create_organization(
    payload: OrganizationCreate,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    try:
        organization = container.organizations.register(
            db,
            base,
            name=payload.name,
            che_uid=payload.che_uid,
            gln=payload.gln,
            kind=payload.kind,
            community=payload.community,
        )
    except PersonError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return OrganizationOut(
        uid=organization.uid,
        name=organization.name,
        che_uid=(
            CheUid(organization.che_uid).formatted() if organization.che_uid else None
        ),
        gln=organization.gln,
        kind=organization.kind,
        community=organization.community,
        active=organization.active,
    )


@router.post(
    "/persons",
    response_model=PersonOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def register_person(
    payload: PersonCreate,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Register a person and derive their pseudonymous identity.

    The AHV number is consumed here and is not stored in any queryable form;
    what comes back is the UID and the derived sector identifier.
    """
    registration = PersonRegistration(
        roles=[PersonRoleKind(r) for r in payload.roles],
        given_name=payload.given_name,
        family_name=payload.family_name,
        ahvn13=payload.ahvn13,
        birth_date=payload.birth_date,
        administrative_sex=payload.administrative_sex,
        email=str(payload.email) if payload.email else None,
        phone=payload.phone,
        identification_method=payload.identification_method,
        id_document=payload.id_document,
        veka_number=payload.veka_number,
    )
    try:
        person = container.persons.register(db, registration, base)
    except DuplicatePersonError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "already registered", "person_uid": exc.existing_uid},
        ) from exc
    except (PersonError, IdentifierError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _to_out(container, db, person)


@router.post("/persons/lookup", response_model=PersonOut, dependencies=[AdminKeyDep])
def lookup_person(
    payload: PersonLookup,
    db: DbDep,
    container: ContainerDep,
):
    """Resolve a person by AHV number or sector identifier."""
    if bool(payload.ahvn13) == bool(payload.spid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="give exactly one of ahvn13 or spid",
        )
    try:
        person = (
            container.persons.find_by_ahvn(db, payload.ahvn13)
            if payload.ahvn13
            else container.persons.find_by_spid(db, payload.spid or "")
        )
    except IdentifierError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    if person is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return _to_out(container, db, person)


@router.get("/persons/me", response_model=PersonOut)
def read_self(db: DbDep, container: ContainerDep, user: CurrentUserDep):
    user.require_scope(Scope.PERSON_READ)
    person = container.persons.get(db, user.claims.subject_uid)
    return _to_out(container, db, person)


@router.patch("/persons/me/contact", response_model=PersonOut)
def update_own_contact(
    payload: ContactUpdate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """Patients maintain their own contact details; the change is versioned."""
    user.require_scope(Scope.PERSON_READ)
    person = container.persons.get(db, user.claims.subject_uid)
    container.persons.update_contact(
        db,
        person,
        user.actor,
        email=str(payload.email) if payload.email else None,
        phone=payload.phone,
        reason=payload.reason,
    )
    return _to_out(container, db, person)


# --------------------------------------------------------------------------
# Roles and professional credentials
# --------------------------------------------------------------------------


@router.post(
    "/persons/{person_uid}/roles",
    response_model=RoleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def grant_role(
    person_uid: str,
    payload: RoleGrant,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Grant a role to an existing person.

    This is how a physician already registered here becomes a patient too —
    one person, one UID, one pseudonym, a second role.
    """
    try:
        person = container.persons.get(db, person_uid)
        assignment = container.persons.grant_role(
            db,
            person,
            base,
            role=PersonRoleKind(payload.role),
            valid_until=payload.valid_until,
            note=payload.note,
        )
    except PersonError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return RoleOut(
        uid=assignment.uid,
        role=assignment.role,
        status=assignment.status,
        valid_from=assignment.valid_from,
        valid_until=assignment.valid_until,
    )


@router.get(
    "/persons/{person_uid}/roles",
    response_model=list[RoleOut],
    dependencies=[AdminKeyDep],
)
def list_roles(person_uid: str, db: DbDep, container: ContainerDep):
    return [
        RoleOut(
            uid=r.uid,
            role=r.role,
            status=r.status,
            valid_from=r.valid_from,
            valid_until=r.valid_until,
        )
        for r in container.persons.roles(db, person_uid)
    ]


@router.post(
    "/persons/{person_uid}/credentials",
    response_model=CredentialOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def register_credential(
    person_uid: str,
    payload: CredentialCreate,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Record a GLN, a federal register entry and a cantonal practice licence.

    Granting the professional role is part of this: a healthcare professional
    without a credential is the state this model exists to make impossible.
    """
    try:
        person = container.persons.get(db, person_uid)
        credential = container.persons.register_credential(
            db,
            person,
            base,
            CredentialRegistration(
                gln=payload.gln,
                register=payload.professional_register,
                profession=payload.profession,
                specialisation=payload.specialisation,
                licence_canton=payload.licence_canton,
                licence_number=payload.licence_number,
                licence_valid_from=payload.licence_valid_from,
                licence_valid_until=payload.licence_valid_until,
                zsr_number=payload.zsr_number,
                organization_uid=payload.organization_uid,
            ),
        )
    except (PersonError, IdentifierError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _credential_out(container, db, credential)


@router.post(
    "/credentials/{credential_uid}/verify",
    response_model=CredentialOut,
    dependencies=[AdminKeyDep],
)
def verify_credential(
    credential_uid: str,
    payload: CredentialVerify,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Record that the credential was checked against MedReg/NAREG/PsyReg.

    The lookup itself belongs to whichever register interface the deployment
    uses; what belongs here is the evidence that it happened.
    """
    from ehealth.models.core import ProfessionalCredential

    credential = db.get(ProfessionalCredential, credential_uid)
    if credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        container.persons.verify_credential(
            db, credential, base, source=payload.source, evidence=payload.evidence
        )
    except PersonError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _credential_out(container, db, credential)


@router.get(
    "/persons/{person_uid}/credentials",
    response_model=list[CredentialOut],
    dependencies=[AdminKeyDep],
)
def list_credentials(person_uid: str, db: DbDep, container: ContainerDep):
    return [
        _credential_out(container, db, c)
        for c in container.persons.credentials(db, person_uid)
    ]
