# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""FastAPI dependencies: request context, database session, authentication."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from ehealth.container import Container, get_container
from ehealth.db import get_session_factory
from ehealth.domain.uid import new_uid
from ehealth.models.auth import AuthSession
from ehealth.security.crypto import KeyPurpose, b64u
from ehealth.security.tokens import Scope, TokenClaims
from ehealth.services.access import AccessError, AuthorizedAccess
from ehealth.services.audit import ActorContext
from ehealth.services.auth import AuthError
from ehealth.services.iua import IuaAccess, IuaError, looks_like_iua_token


def container_dep() -> Container:
    return get_container()


ContainerDep = Annotated[Container, Depends(container_dep)]


def db_session() -> Iterator[Session]:
    """One transaction per request.

    Committing here rather than inside services is what makes an audit entry
    and the change it describes atomic — a handler that raises leaves neither
    behind.
    """
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


#: ``scope="function"`` is load-bearing. With the default request scope,
#: FastAPI runs the commit *after* the handler's response has been built, and
#: a commit that fails there still reaches the client as ``200 OK`` — a write
#: acknowledged and then rolled back. Function scope commits before the
#: response exists, so a failed commit is a 5xx and nothing was claimed.
DbDep = Annotated[Session, Depends(db_session, scope="function")]


def hash_client_ip(container: Container, request: Request) -> str | None:
    """Keyed hash of the client address.

    Enough to correlate requests during an incident, not enough to build a
    movement profile or to identify a subscriber after the fact.
    """
    client = request.client
    if client is None:
        return None
    return b64u(
        container.keyring.mac(KeyPurpose.OTP_BINDING, f"ip|{client.host}".encode())
    )[:32]


def request_context(
    request: Request,
    container: ContainerDep,
    x_request_id: Annotated[str | None, Header()] = None,
) -> ActorContext:
    """Anonymous request context, before any token is checked."""
    return ActorContext(
        actor_uid=None,
        actor_kind="anonymous",
        request_id=x_request_id or new_uid("req"),
        client_ip_hash=hash_client_ip(container, request),
        user_agent=request.headers.get("user-agent"),
    )


RequestContextDep = Annotated[ActorContext, Depends(request_context)]


def bearer_token(
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return authorization.split(" ", 1)[1].strip()


BearerDep = Annotated[str, Depends(bearer_token)]


@dataclass(frozen=True, slots=True)
class CurrentUser:
    claims: TokenClaims
    session: AuthSession
    actor: ActorContext

    def require_scope(self, scope: Scope) -> None:
        if not self.claims.has_scope(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"scope {scope.value} is required",
            )


def current_user(
    token: BearerDep,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
) -> CurrentUser:
    """Resolve an interactive session token to its person."""
    try:
        claims, auth_session = container.auth.verify_session_token(db, token)
    except AuthError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    actor = ActorContext(
        actor_uid=claims.subject_uid,
        actor_kind="person",
        organization_uid=claims.organization_uid,
        purpose=claims.purpose,
        token_jti=claims.jti,
        request_id=base.request_id,
        client_ip_hash=base.client_ip_hash,
        user_agent=base.user_agent,
    )
    return CurrentUser(claims=claims, session=auth_session, actor=actor)


CurrentUserDep = Annotated[CurrentUser, Depends(current_user)]


def capability_access(required_scope: Scope):
    """Build a dependency that authorises a capability token for one scope.

    Usage::

        access: Annotated[AuthorizedAccess, Depends(capability_access(Scope.DOSSIER_READ))]

    The capability token travels in ``X-Capability`` rather than
    ``Authorization`` so that a session token and a dossier capability can be
    presented together without either standing in for the other.
    """

    def dependency(
        db: DbDep,
        container: ContainerDep,
        base: RequestContextDep,
        x_capability: Annotated[str | None, Header()] = None,
        x_holder_key: Annotated[str | None, Header()] = None,
    ) -> AuthorizedAccess:
        if not x_capability:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="a capability token is required",
            )
        try:
            return container.access.authorize(
                db,
                x_capability,
                required_scope=required_scope,
                holder_key_b64=x_holder_key,
                request_context=base,
            )
        except AccessError as exc:
            # The ledger already holds the real reason; the caller gets none.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="access denied"
            ) from exc

    return dependency


# --------------------------------------------------------------------------
# The national FHIR interfaces: IUA tokens (CH EPR FHIR v5.0.0, ITI-72)
# --------------------------------------------------------------------------


def _bearer_value(authorization: str | None) -> str | None:
    if authorization and authorization[:7].lower() == "bearer ":
        return authorization[7:].strip() or None
    return None


def _unauthenticated(error: str = "invalid_token") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="not authenticated",
        headers={"WWW-Authenticate": f'Bearer error="{error}"'},
    )


def _iua(
    container: Container,
    db: Session,
    token: str,
    *,
    scope: Scope,
    extended: bool,
    base: ActorContext,
) -> IuaAccess:
    try:
        return container.iua.authorize_request(
            db, token, required_scope=scope, extended=extended, request_context=base
        )
    except IuaError as exc:
        # The ledger holds the reason; the caller learns nothing about the
        # record from a refusal.
        raise _unauthenticated() from exc


#: What the MHD transactions authorise with: an IUA token, or this system's
#: own capability. Both expose ``dossier_uid``, ``max_level``, ``actor`` and
#: ``subject_uid``, which is all the dossier services read.
DocumentAccess = AuthorizedAccess | IuaAccess


def document_access(required_scope: Scope):
    """MHD authorisation (ITI-65/67/68).

    ``Authorization: Bearer <IUA extended access token>`` is the national
    interface. A capability in ``X-Capability`` — alongside this system's
    own session token in ``Authorization``, for the same person — stays
    accepted for this system's own portal. Presenting both kinds at once is
    refused: which authority a request used must never be ambiguous.
    """

    def dependency(
        db: DbDep,
        container: ContainerDep,
        base: RequestContextDep,
        authorization: Annotated[str | None, Header()] = None,
        x_capability: Annotated[str | None, Header()] = None,
        x_holder_key: Annotated[str | None, Header()] = None,
    ) -> DocumentAccess:
        token = _bearer_value(authorization)
        if token is not None and looks_like_iua_token(token):
            if x_capability:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="present an IUA token or a capability, not both",
                )
            return _iua(
                container, db, token, scope=required_scope, extended=True, base=base
            )
        if not x_capability or token is None:
            raise _unauthenticated("invalid_request")
        try:
            claims, _ = container.auth.verify_session_token(db, token)
        except AuthError as exc:
            raise _unauthenticated() from exc
        try:
            access = container.access.authorize(
                db,
                x_capability,
                required_scope=required_scope,
                holder_key_b64=x_holder_key,
                request_context=base,
            )
        except AccessError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="access denied"
            ) from exc
        if access.subject_uid != claims.subject_uid:
            # A capability is personal: the session presenting it must be
            # its grantee's.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="access denied"
            )
        return access

    return dependency


def directory_actor(
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
    authorization: Annotated[str | None, Header()] = None,
) -> ActorContext:
    """PIXm/PDQm: an IUA basic (or extended) token, or a session token.

    Either way the directory then requires the healthcare-professional role;
    the token only says who is asking.
    """
    token = _bearer_value(authorization)
    if token is None:
        raise _unauthenticated("invalid_request")
    if looks_like_iua_token(token):
        return _iua(
            container, db, token, scope=Scope.PERSON_READ, extended=False, base=base
        ).actor
    return current_user(token, db, container, base).actor


DirectoryActorDep = Annotated[ActorContext, Depends(directory_actor)]


@dataclass(frozen=True, slots=True)
class AuditTrailReader:
    """Who is asking for a patient audit trail (CH:ATC), and whether the
    authority they present covers ``audit:read``."""

    subject_uid: str
    may_read_audit: bool


def audit_trail_reader(
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
    authorization: Annotated[str | None, Header()] = None,
) -> AuditTrailReader:
    token = _bearer_value(authorization)
    if token is None:
        raise _unauthenticated("invalid_request")
    if looks_like_iua_token(token):
        # ITI-81 takes an extended token; only the patient role carries
        # audit:read, so a professional's token is refused here.
        access = _iua(
            container, db, token, scope=Scope.AUDIT_READ, extended=True, base=base
        )
        return AuditTrailReader(access.subject_uid, True)
    user = current_user(token, db, container, base)
    return AuditTrailReader(
        user.claims.subject_uid, user.claims.has_scope(Scope.AUDIT_READ)
    )


AuditTrailReaderDep = Annotated[AuditTrailReader, Depends(audit_trail_reader)]
