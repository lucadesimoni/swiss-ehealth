"""Medication catalogue and per-patient medication record."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from ehealth.api.deps import (
    ContainerDep,
    CurrentUserDep,
    DbDep,
    RequestContextDep,
    capability_access,
)
from ehealth.api.routes_auth import AdminKeyDep
from ehealth.api.schemas import (
    DosageUpdate,
    MedicationCreate,
    MedicationOut,
    ProductCreate,
    ProductOut,
    StopMedicationIn,
)
from ehealth.models.clinical import MedicationEventKind
from ehealth.security.tokens import Scope
from ehealth.services.access import AuthorizedAccess
from ehealth.services.medication import (
    MedicationError,
    ProductInput,
    StatementInput,
)

router = APIRouter(tags=["medication"])

MedRead = Annotated[
    AuthorizedAccess, Depends(capability_access(Scope.MEDICATION_READ))
]
MedWrite = Annotated[
    AuthorizedAccess, Depends(capability_access(Scope.MEDICATION_WRITE))
]


def _product_out(product) -> ProductOut:
    return ProductOut(
        uid=product.uid,
        gtin=product.gtin,
        name=product.name,
        swissmedic_authorisation=product.swissmedic_authorisation,
        active_ingredient=product.active_ingredient,
        atc_code=product.atc_code,
        dose_form=product.dose_form,
        strength=product.strength,
        package_size=product.package_size,
        narcotic=product.narcotic,
        prescription_only=product.prescription_only,
        version=product.version,
    )


def _statement_out(statement) -> MedicationOut:
    return MedicationOut(
        uid=statement.uid,
        dossier_uid=statement.dossier_uid,
        kind=statement.kind,
        status=statement.status,
        confidentiality=statement.confidentiality,
        product_uid=statement.product_uid,
        product_text=statement.product_text,
        dosage=statement.dosage,
        quantity=statement.quantity,
        reason=statement.reason,
        effective_start=statement.effective_start,
        effective_end=statement.effective_end,
        recorded_by_uid=statement.recorded_by_uid,
        organization_uid=statement.organization_uid,
        based_on_uid=statement.based_on_uid,
        version=statement.version,
    )


# -- catalogue ------------------------------------------------------------


@router.post(
    "/products",
    response_model=ProductOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def register_product(
    payload: ProductCreate,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Add a package to the medicinal product catalogue (GTIN-keyed)."""
    try:
        product = container.catalogue.register(
            db,
            base,
            ProductInput(
                gtin=payload.gtin,
                name=payload.name,
                swissmedic_authorisation=payload.swissmedic_authorisation,
                active_ingredient=payload.active_ingredient,
                atc_code=payload.atc_code,
                dose_form=payload.dose_form,
                strength=payload.strength,
                package_size=payload.package_size,
                marketing_authorisation_holder=payload.marketing_authorisation_holder,
                narcotic=payload.narcotic,
                prescription_only=payload.prescription_only,
            ),
        )
    except MedicationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _product_out(product)


@router.get("/products", response_model=list[ProductOut])
def search_products(
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    q: Annotated[str, Query(min_length=2, max_length=120)],
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
):
    """Catalogue search. Product data is not patient data, so a logged-in
    session is enough — no capability token required."""
    products = container.catalogue.search(db, q, limit=limit)
    return [_product_out(product) for product in products]


# -- patient medication ---------------------------------------------------


@router.get("/dossiers/{dossier_uid}/medications", response_model=list[MedicationOut])
def list_medications(
    dossier_uid: Annotated[str, Path()],
    db: DbDep,
    container: ContainerDep,
    access: MedRead,
    kind: Annotated[MedicationEventKind | None, Query()] = None,
    active_only: Annotated[bool, Query()] = False,
):
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    rows = container.medications.list_for_dossier(
        db, access, kinds=[kind] if kind else None, active_only=active_only
    )
    return [_statement_out(row) for row in rows]


@router.get(
    "/dossiers/{dossier_uid}/medications/reconciled",
    response_model=list[MedicationOut],
)
def reconciled_medications(
    dossier_uid: Annotated[str, Path()],
    db: DbDep,
    container: ContainerDep,
    access: MedRead,
):
    """The current medication list a clinician should act on."""
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    return [_statement_out(row) for row in container.medications.reconciled_list(db, access)]


@router.post(
    "/dossiers/{dossier_uid}/medications",
    response_model=MedicationOut,
    status_code=status.HTTP_201_CREATED,
)
def record_medication(
    dossier_uid: Annotated[str, Path()],
    payload: MedicationCreate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    access: MedWrite,
):
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    actor = container.persons.get(db, user.claims.subject_uid)
    try:
        statement = container.medications.record(
            db,
            access,
            StatementInput(
                kind=MedicationEventKind(payload.kind),
                product_uid=payload.product_uid,
                product_text=payload.product_text,
                dosage=payload.dosage,
                quantity=payload.quantity,
                reason=payload.reason,
                effective_start=payload.effective_start,
                effective_end=payload.effective_end,
                confidentiality=payload.confidentiality,
                based_on_uid=payload.based_on_uid,
            ),
            recorded_by_uid=actor.uid,
            organization_uid=actor.organization_uid,
        )
    except MedicationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return _statement_out(statement)


@router.post(
    "/dossiers/{dossier_uid}/medications/{statement_uid}/stop",
    response_model=MedicationOut,
)
def stop_medication(
    dossier_uid: Annotated[str, Path()],
    statement_uid: Annotated[str, Path()],
    payload: StopMedicationIn,
    db: DbDep,
    container: ContainerDep,
    access: MedWrite,
):
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        statement = container.medications.stop(
            db,
            access,
            statement_uid,
            reason=payload.reason,
            effective_end=payload.effective_end,
        )
    except MedicationError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return _statement_out(statement)


@router.patch(
    "/dossiers/{dossier_uid}/medications/{statement_uid}/dosage",
    response_model=MedicationOut,
)
def update_dosage(
    dossier_uid: Annotated[str, Path()],
    statement_uid: Annotated[str, Path()],
    payload: DosageUpdate,
    db: DbDep,
    container: ContainerDep,
    access: MedWrite,
):
    """Change a dosage. The previous value stays in the revision history."""
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        statement = container.medications.update_dosage(
            db, access, statement_uid, dosage=payload.dosage, reason=payload.reason
        )
    except MedicationError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return _statement_out(statement)


@router.post(
    "/dossiers/{dossier_uid}/medications/{statement_uid}/entered-in-error",
    response_model=MedicationOut,
)
def mark_entered_in_error(
    dossier_uid: Annotated[str, Path()],
    statement_uid: Annotated[str, Path()],
    payload: StopMedicationIn,
    db: DbDep,
    container: ContainerDep,
    access: MedWrite,
):
    """Flag a mistaken entry. It stays visible in the history."""
    if access.dossier_uid != dossier_uid:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    try:
        statement = container.medications.mark_entered_in_error(
            db, access, statement_uid, reason=payload.reason
        )
    except MedicationError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    return _statement_out(statement)
