"""Person and institution registry."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, status

from ehealth.api.deps import ContainerDep, CurrentUserDep, DbDep, RequestContextDep
from ehealth.api.routes_auth import AdminKeyDep
from ehealth.api.schemas import (
    ContactUpdate,
    OrganizationCreate,
    OrganizationOut,
    PersonCreate,
    PersonLookup,
    PersonOut,
)
from ehealth.domain.uid import CheUid, IdentifierError
from ehealth.models.core import PersonKind
from ehealth.security.tokens import Scope
from ehealth.services.persons import (
    DuplicatePersonError,
    PersonError,
    PersonRegistration,
)

router = APIRouter(tags=["registry"])


def _to_out(container, person) -> PersonOut:
    view = container.persons.view(person)
    return PersonOut(**asdict(view))


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
        kind=PersonKind(payload.kind),
        given_name=payload.given_name,
        family_name=payload.family_name,
        ahvn13=payload.ahvn13,
        birth_date=payload.birth_date,
        administrative_sex=payload.administrative_sex,
        email=str(payload.email) if payload.email else None,
        phone=payload.phone,
        identification_method=payload.identification_method,
        id_document=payload.id_document,
        gln=payload.gln,
        profession=payload.profession,
        organization_uid=payload.organization_uid,
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
    return _to_out(container, person)


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
    return _to_out(container, person)


@router.get("/persons/me", response_model=PersonOut)
def read_self(db: DbDep, container: ContainerDep, user: CurrentUserDep):
    user.require_scope(Scope.PERSON_READ)
    person = container.persons.get(db, user.claims.subject_uid)
    return _to_out(container, person)


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
    return _to_out(container, person)
