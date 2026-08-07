"""Consent, grants, visitor access, capability minting and break-glass."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Path, status

from ehealth.api.deps import ContainerDep, CurrentUserDep, DbDep
from ehealth.api.schemas import (
    CapabilityOut,
    ConsentCreate,
    ConsentOut,
    ConsentRuleCreate,
    ConsentRuleOut,
    ConsentUpdate,
    EmergencyAccessIn,
    GrantCreate,
    GrantOut,
    RevokeIn,
    VisitorGrantCreate,
)
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.core import PersonKind
from ehealth.models.governance import AccessGrant, RuleEffect
from ehealth.security.tokens import Scope, TokenError
from ehealth.services.access import AccessError, ConsentError
from ehealth.services.dossier import DossierError
from ehealth.services.persons import PersonError

router = APIRouter(tags=["access"])


def _grant_out(grant: AccessGrant) -> GrantOut:
    return GrantOut(
        uid=grant.uid,
        dossier_uid=grant.dossier_uid,
        grantee_uid=grant.grantee_uid,
        grantee_kind=grant.grantee_kind,
        purpose=grant.purpose,
        access_level=grant.access_level,
        scopes=list(grant.scopes),
        valid_from=grant.valid_from,
        valid_until=grant.valid_until,
        status=grant.status,
        max_uses=grant.max_uses,
        use_count=grant.use_count,
    )


def _parse_scopes(values: list[str]) -> list[Scope]:
    try:
        return Scope.parse_all(values)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc


# --------------------------------------------------------------------------
# Consent
# --------------------------------------------------------------------------


@router.post("/consent", response_model=ConsentOut, status_code=status.HTTP_201_CREATED)
def record_consent(
    payload: ConsentCreate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """A patient joins. Consent is theirs to give, so only they may record it."""
    user.require_scope(Scope.CONSENT_WRITE)
    patient = container.persons.get(db, user.claims.subject_uid)
    try:
        consent = container.consents.record(
            db,
            user.actor,
            patient=patient,
            default_access_level=payload.default_access_level,
            emergency_access_allowed=payload.emergency_access_allowed,
            notify_on_access=payload.notify_on_access,
            evidence={**payload.evidence, "session_uid": user.session.uid},
        )
    except ConsentError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    return ConsentOut(**_consent_fields(consent))


def _consent_fields(consent) -> dict:
    return {
        "uid": consent.uid,
        "patient_uid": consent.patient_uid,
        "participation": consent.participation,
        "default_access_level": consent.default_access_level,
        "emergency_access_allowed": consent.emergency_access_allowed,
        "notify_on_access": consent.notify_on_access,
        "version": consent.version,
    }


@router.get("/consent", response_model=ConsentOut)
def read_consent(db: DbDep, container: ContainerDep, user: CurrentUserDep):
    user.require_scope(Scope.CONSENT_READ)
    consent = container.consents.for_patient(db, user.claims.subject_uid)
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return ConsentOut(**_consent_fields(consent))


@router.patch("/consent", response_model=ConsentOut)
def update_consent(
    payload: ConsentUpdate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    user.require_scope(Scope.CONSENT_WRITE)
    consent = container.consents.for_patient(db, user.claims.subject_uid)
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    container.consents.update(
        db,
        user.actor,
        consent,
        default_access_level=payload.default_access_level,
        emergency_access_allowed=payload.emergency_access_allowed,
        notify_on_access=payload.notify_on_access,
        reason=payload.reason,
    )
    return ConsentOut(**_consent_fields(consent))


@router.post("/consent/withdraw", response_model=ConsentOut)
def withdraw_consent(
    payload: RevokeIn,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """Leave the system. Every outstanding grant and token dies with it."""
    user.require_scope(Scope.CONSENT_WRITE)
    consent = container.consents.for_patient(db, user.claims.subject_uid)
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    container.consents.withdraw(db, user.actor, consent, reason=payload.reason)
    return ConsentOut(**_consent_fields(consent))


@router.post(
    "/consent/rules",
    response_model=ConsentRuleOut,
    status_code=status.HTTP_201_CREATED,
)
def add_consent_rule(
    payload: ConsentRuleCreate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """Allow or exclude a specific professional or institution."""
    user.require_scope(Scope.CONSENT_WRITE)
    consent = container.consents.for_patient(db, user.claims.subject_uid)
    if consent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        rule = container.consents.add_rule(
            db,
            user.actor,
            consent,
            subject_type=payload.subject_type,
            subject_uid=payload.subject_uid,
            effect=RuleEffect(payload.effect),
            access_level=payload.access_level,
            valid_until=payload.valid_until,
            note=payload.note,
        )
    except ConsentError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    return ConsentRuleOut(
        uid=rule.uid,
        subject_type=rule.subject_type,
        subject_uid=rule.subject_uid,
        effect=rule.effect,
        access_level=rule.access_level,
        valid_from=rule.valid_from,
        valid_until=rule.valid_until,
    )


# --------------------------------------------------------------------------
# Grants
# --------------------------------------------------------------------------


@router.post("/grants", response_model=GrantOut, status_code=status.HTTP_201_CREATED)
def create_grant(
    payload: GrantCreate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """Grant a professional bounded access to a dossier."""
    user.require_scope(Scope.GRANT_MANAGE)
    try:
        dossier = container.dossiers.get(db, payload.dossier_uid)
        grantee = container.persons.get(db, payload.grantee_uid)
        granter = container.persons.get(db, user.claims.subject_uid)
    except (DossierError, PersonError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc

    # Only the patient may hand out access to their own record; a professional
    # cannot grant themselves anything.
    if granter.uid != dossier.patient_uid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only the patient may grant access to their dossier",
        )
    try:
        grant = container.access.issue_grant(
            db,
            user.actor,
            dossier=dossier,
            grantee=grantee,
            granted_by=granter,
            purpose=Purpose(payload.purpose),
            scopes=_parse_scopes(payload.scopes),
            ttl_seconds=payload.ttl_seconds,
            access_level=payload.access_level,
            max_uses=payload.max_uses,
            note=payload.note,
        )
    except AccessError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    return _grant_out(grant)


@router.post(
    "/grants/visitor", response_model=GrantOut, status_code=status.HTTP_201_CREATED
)
def create_visitor_grant(
    payload: VisitorGrantCreate,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """Give a visitor time-boxed, read-only, use-capped access.

    Scopes are clamped to the visitor ceiling regardless of what was asked
    for, and the grant expires on its own — a visitor's access is never
    something someone has to remember to take away.
    """
    user.require_scope(Scope.GRANT_MANAGE)
    patient = container.persons.get(db, user.claims.subject_uid)
    dossier = container.dossiers.for_patient(db, patient.uid)
    if dossier is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no dossier for this patient"
        )
    visitor = container.persons.get(db, payload.visitor_uid)
    if PersonKind(visitor.kind) is not PersonKind.VISITOR:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grantee is not registered as a visitor",
        )
    try:
        grant = container.access.issue_grant(
            db,
            user.actor,
            dossier=dossier,
            grantee=visitor,
            granted_by=patient,
            purpose=Purpose.TREATMENT,
            scopes=_parse_scopes(payload.scopes),
            ttl_seconds=payload.ttl_seconds,
            max_uses=payload.max_uses,
            note=payload.note,
        )
    except AccessError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    return _grant_out(grant)


@router.post("/grants/{grant_uid}/revoke", response_model=GrantOut)
def revoke_grant(
    grant_uid: Annotated[str, Path()],
    payload: RevokeIn,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    user.require_scope(Scope.GRANT_MANAGE)
    grant = db.get(AccessGrant, grant_uid)
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    dossier = container.dossiers.get(db, grant.dossier_uid)
    if user.claims.subject_uid not in (dossier.patient_uid, grant.granted_by_uid):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    container.access.revoke_grant(db, user.actor, grant, reason=payload.reason)
    return _grant_out(grant)


# --------------------------------------------------------------------------
# Capability tokens
# --------------------------------------------------------------------------


@router.post("/grants/{grant_uid}/token", response_model=CapabilityOut)
def mint_capability(
    grant_uid: Annotated[str, Path()],
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
    holder_key: Annotated[str | None, Body(embed=True)] = None,
):
    """Exchange a grant for a short-lived capability token.

    Supplying ``holder_key`` binds the token to that key, so a stolen token is
    useless without the corresponding private key.
    """
    grant = db.get(AccessGrant, grant_uid)
    if grant is None or grant.grantee_uid != user.claims.subject_uid:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        capability = container.access.mint(
            db,
            user.actor,
            grant=grant,
            session_uid=user.session.uid,
            holder_key_b64=holder_key,
        )
    except AccessError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    return CapabilityOut(
        token=capability.token,
        jti=capability.jti,
        grant_uid=capability.grant_uid,
        expires_at=capability.expires_at,
        scopes=list(capability.scopes),
        access_level=capability.access_level,
    )


@router.post("/access/self", response_model=CapabilityOut)
def self_capability(db: DbDep, container: ContainerDep, user: CurrentUserDep):
    """A patient's capability on their own dossier, at every level."""
    patient = container.persons.get(db, user.claims.subject_uid)
    dossier = container.dossiers.for_patient(db, patient.uid)
    if dossier is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="no dossier for this patient"
        )
    grant = container.access.issue_grant(
        db,
        user.actor,
        dossier=dossier,
        grantee=patient,
        granted_by=patient,
        purpose=Purpose.PATIENT_ACCESS,
        scopes=[
            Scope.DOSSIER_READ,
            Scope.DOSSIER_WRITE,
            Scope.DOCUMENT_READ,
            Scope.DOCUMENT_WRITE,
            Scope.MEDICATION_READ,
            Scope.MEDICATION_WRITE,
            Scope.AUDIT_READ,
        ],
        access_level=Confidentiality.SECRET,
    )
    capability = container.access.mint(
        db, user.actor, grant=grant, session_uid=user.session.uid
    )
    return CapabilityOut(
        token=capability.token,
        jti=capability.jti,
        grant_uid=capability.grant_uid,
        expires_at=capability.expires_at,
        scopes=list(capability.scopes),
        access_level=capability.access_level,
    )


@router.post("/access/emergency", response_model=CapabilityOut)
def emergency_access(
    payload: EmergencyAccessIn,
    db: DbDep,
    container: ContainerDep,
    user: CurrentUserDep,
):
    """Break-glass access for a treating professional.

    Loud by design: the grant, the token and every subsequent use are audited,
    the patient is flagged for notification, and the ceiling stays below
    SECRET. A justification is mandatory and is recorded verbatim.
    """
    professional = container.persons.get(db, user.claims.subject_uid)
    if not professional.is_professional():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="only healthcare professionals may invoke emergency access",
        )
    patient = container.persons.get(db, payload.patient_uid)
    dossier = container.dossiers.for_patient(db, patient.uid)
    if dossier is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    try:
        grant = container.access.issue_grant(
            db,
            user.actor,
            dossier=dossier,
            grantee=professional,
            granted_by=patient,
            purpose=Purpose.EMERGENCY,
            scopes=[
                Scope.DOSSIER_READ,
                Scope.DOCUMENT_READ,
                Scope.MEDICATION_READ,
            ],
            note=payload.justification,
        )
        capability = container.access.mint(
            db, user.actor, grant=grant, session_uid=user.session.uid
        )
    except AccessError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)
        ) from exc
    return CapabilityOut(
        token=capability.token,
        jti=capability.jti,
        grant_uid=capability.grant_uid,
        expires_at=capability.expires_at,
        scopes=list(capability.scopes),
        access_level=capability.access_level,
    )
