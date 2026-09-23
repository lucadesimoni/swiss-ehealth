# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Login endpoints: identity providers, second factor, session lifecycle."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status

from ehealth.api.deps import (
    ContainerDep,
    CurrentUserDep,
    DbDep,
    RequestContextDep,
)
from ehealth.api.schemas import (
    AccountLinkIn,
    IdentityProvidersOut,
    LoginCallbackIn,
    LoginChallengeOut,
    LoginStartOut,
    OtpResendIn,
    OtpVerifyIn,
    RefreshIn,
    SessionOut,
)
from ehealth.security.crypto import constant_time_equals
from ehealth.services.auth import DEFAULT_PROVIDER, AuthError, SessionTokens

router = APIRouter(prefix="/auth", tags=["authentication"])


def require_admin_key(
    container: ContainerDep,
    x_admin_key: Annotated[str | None, Header()] = None,
) -> None:
    """Guard for enrolment endpoints called by back-office systems.

    Absent configuration means the endpoints are off — a deployment that
    forgot to set a key does not get a default one.
    """
    configured = container.settings.admin_api_key
    if not configured:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    if not x_admin_key or not constant_time_equals(x_admin_key, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated"
        )


AdminKeyDep = Depends(require_admin_key)


def _session_out(tokens: SessionTokens) -> SessionOut:
    return SessionOut(
        session_uid=tokens.session_uid,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=tokens.expires_at,
        person_uid=tokens.person_uid,
        scopes=list(tokens.scopes),
    )


@router.get("/providers", response_model=IdentityProvidersOut)
def list_providers(container: ContainerDep):
    """Which identity providers a login page may offer.

    Names only: issuers, client ids and policies stay server-side.
    """
    return IdentityProvidersOut(
        providers=list(container.auth.provider_names), default=DEFAULT_PROVIDER
    )


@router.get("/jwks.json")
def client_jwks(container: ContainerDep):
    """Our public signing keys for ``private_key_jwt`` client authentication.

    Registered with (or fetched by) each identity provider so it can verify
    the assertions this service signs at the token endpoint. Public by
    design; empty when every provider still uses a client secret.
    """
    keys: list[dict] = []
    for provider in container.identity_providers.values():
        publish = getattr(provider, "public_jwks", None)
        if publish is not None:
            for key in publish()["keys"]:
                if key not in keys:
                    keys.append(key)
    return {"keys": keys}


@router.post("/login", response_model=LoginStartOut)
def start_login(
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
    provider: Annotated[str, Query(max_length=32)] = DEFAULT_PROVIDER,
):
    """Begin the authorisation code flow at the chosen identity provider."""
    try:
        url, state = container.auth.begin_login(db, base, provider=provider)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unknown identity provider",
        ) from exc
    return LoginStartOut(authorization_url=url, state=state)


@router.post("/callback", response_model=LoginChallengeOut)
def complete_login(
    payload: LoginCallbackIn,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Exchange the authorisation code, then complete the second factor.

    With ``second_factor == "otp-email"`` this is *not* a login yet: the
    session is ``PENDING_MFA`` and can do nothing until the emailed code is
    verified. With ``"idp"`` the provider already verified two factors and
    ``session`` carries the tokens.
    """
    try:
        challenge = container.auth.complete_login(
            db, base, state=payload.state, code=payload.code
        )
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed"
        ) from exc
    return LoginChallengeOut(
        session_uid=challenge.session_uid,
        masked_email=challenge.masked_email,
        expires_at=challenge.expires_at,
        attempts_remaining=challenge.attempts_remaining,
        second_factor=challenge.second_factor,
        session=_session_out(challenge.tokens) if challenge.tokens else None,
    )


@router.post("/mfa/verify", response_model=SessionOut)
def verify_otp(
    payload: OtpVerifyIn,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    try:
        tokens = container.auth.verify_otp(
            db, base, session_uid=payload.session_uid, code=payload.code
        )
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed"
        ) from exc
    return SessionOut(
        session_uid=tokens.session_uid,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=tokens.expires_at,
        person_uid=tokens.person_uid,
        scopes=list(tokens.scopes),
    )


@router.post("/mfa/resend", response_model=LoginChallengeOut)
def resend_otp(
    payload: OtpResendIn,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Send a fresh code and invalidate the previous one."""
    try:
        challenge = container.auth.resend_otp(db, base, session_uid=payload.session_uid)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed"
        ) from exc
    return LoginChallengeOut(
        session_uid=challenge.session_uid,
        masked_email=challenge.masked_email,
        expires_at=challenge.expires_at,
        attempts_remaining=challenge.attempts_remaining,
    )


@router.post("/refresh", response_model=SessionOut)
def refresh(
    payload: RefreshIn,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Rotate the session. Replaying a spent refresh token kills the session."""
    try:
        tokens = container.auth.refresh(db, base, refresh_token=payload.refresh_token)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc
    return SessionOut(
        session_uid=tokens.session_uid,
        access_token=tokens.access_token,
        refresh_token=tokens.refresh_token,
        expires_at=tokens.expires_at,
        person_uid=tokens.person_uid,
        scopes=list(tokens.scopes),
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(db: DbDep, container: ContainerDep, user: CurrentUserDep):
    container.auth.logout(db, user.actor, session_uid=user.session.uid)


@router.post(
    "/accounts/link",
    status_code=status.HTTP_201_CREATED,
    dependencies=[AdminKeyDep],
)
def link_account(
    payload: AccountLinkIn,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    """Bind a SwissID subject to a registered person.

    Enrolment is deliberately separate from login: a valid federated identity
    this system has never heard of must not be able to create itself an
    account against a health record.
    """
    person = container.persons.get(db, payload.person_uid)
    try:
        account = container.auth.link_account(
            db,
            base,
            person=person,
            issuer=payload.issuer,
            subject=payload.subject,
            email=str(payload.email),
        )
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    return {"account_uid": account.uid, "person_uid": person.uid}
