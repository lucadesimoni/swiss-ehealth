# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Login: SwissID first, emailed one-time code second, then a bound session.

The sequence is deliberate. Proving who you are (SwissID) and proving you
still hold a second factor are separate steps with separate state, and the
session carries *no authority at all* until both have passed — a
``PENDING_MFA`` session cannot be exchanged for any token.

Accounts are never auto-provisioned from a successful federated login.
Someone authenticating with a valid SwissID that this system has never heard
of gets nothing; linking an identity to a person is an explicit enrolment
step, because in a health record the question is not "is this a real person"
but "is this *that* patient".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.identity import IdentityService
from ehealth.domain.uid import new_uid
from ehealth.models.audit import AuditAction, AuditOutcome
from ehealth.models.auth import (
    AccountStatus,
    AssuranceLevel,
    AuthSession,
    IdentityAccount,
    OidcFlow,
    OtpChallenge,
    SessionState,
)
from ehealth.models.core import Person, PersonKind
from ehealth.models.governance import IssuedToken, TokenKind
from ehealth.security.crypto import KeyPurpose, KeyRing
from ehealth.security.mfa import OtpService
from ehealth.security.oidc import IdentityProvider, OidcError, VerifiedIdentity
from ehealth.security.tokens import Scope, TokenClaims, TokenError, TokenService
from ehealth.services.audit import (
    ActorContext,
    AuditLedger,
    commit_security_event,
)

#: What a logged-in person may do with their session token alone, before any
#: dossier-specific capability is minted.
SESSION_SCOPES: dict[PersonKind, tuple[Scope, ...]] = {
    PersonKind.PATIENT: (
        Scope.PERSON_READ,
        Scope.CONSENT_READ,
        Scope.CONSENT_WRITE,
        Scope.GRANT_MANAGE,
        Scope.AUDIT_READ,
    ),
    PersonKind.HEALTHCARE_PROFESSIONAL: (
        Scope.PERSON_READ,
        Scope.GRANT_MANAGE,
    ),
    PersonKind.VISITOR: (Scope.PERSON_READ,),
    PersonKind.REPRESENTATIVE: (Scope.PERSON_READ, Scope.GRANT_MANAGE),
}

OIDC_FLOW_TTL_SECONDS = 600


class AuthError(Exception):
    """Authentication failed. The message is intentionally vague to callers."""


@dataclass(frozen=True, slots=True)
class LoginChallenge:
    """Returned after SwissID succeeds and the OTP has been sent."""

    session_uid: str
    masked_email: str
    expires_at: datetime
    attempts_remaining: int


@dataclass(frozen=True, slots=True)
class SessionTokens:
    session_uid: str
    access_token: str
    refresh_token: str
    expires_at: datetime
    person_uid: str
    scopes: tuple[str, ...]


def mask_email(address: str) -> str:
    """``anna.muster@example.ch`` -> ``a***r@example.ch``."""
    local, _, domain = address.partition("@")
    if not domain:
        return "***"
    if len(local) <= 2:
        return f"{local[0]}***@{domain}"
    return f"{local[0]}***{local[-1]}@{domain}"


class AuthService:
    def __init__(
        self,
        *,
        provider: IdentityProvider,
        tokens: TokenService,
        otp: OtpService,
        identity: IdentityService,
        keyring: KeyRing,
        ledger: AuditLedger,
        session_ttl_seconds: int = 900,
        refresh_ttl_seconds: int = 43_200,
        otp_max_attempts: int = 5,
        max_failed_logins: int = 10,
    ) -> None:
        self._provider = provider
        self._tokens = tokens
        self._otp = otp
        self._identity = identity
        self._keyring = keyring
        self._ledger = ledger
        self._session_ttl = session_ttl_seconds
        self._refresh_ttl = refresh_ttl_seconds
        self._otp_max_attempts = otp_max_attempts
        self._max_failed_logins = max_failed_logins

    # -- enrolment --------------------------------------------------------

    def link_account(
        self,
        session: Session,
        actor: ActorContext,
        *,
        person: Person,
        issuer: str,
        subject: str,
        email: str,
        idp_assurance: AssuranceLevel = AssuranceLevel.AAL1,
    ) -> IdentityAccount:
        """Bind a federated identity to a person. Enrolment, not login."""
        existing = session.execute(
            select(IdentityAccount).where(
                IdentityAccount.issuer == issuer, IdentityAccount.subject == subject
            )
        ).scalars().first()
        if existing is not None:
            raise AuthError("this identity is already linked to an account")
        if self._account_for_person(session, person.uid) is not None:
            raise AuthError("this person already has an account")

        uid = new_uid("usr")
        account = IdentityAccount(
            uid=uid,
            person_uid=person.uid,
            issuer=issuer,
            subject=subject,
            email_enc=self._identity.seal_field(uid, "email", email),
            email_index=self._keyring.blind_index(
                KeyPurpose.PERSON_LOOKUP_INDEX, email.strip().lower().encode("utf-8")
            ),
            email_verified=False,
            idp_assurance=idp_assurance.value,
        )
        session.add(account)
        session.flush()
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.PERSON_UPDATED,
            resource_type="identity_account",
            resource_uid=account.uid,
            detail={"person_uid": person.uid, "issuer": issuer},
        )
        return account

    @staticmethod
    def _account_for_person(session: Session, person_uid: str) -> IdentityAccount | None:
        return (
            session.execute(
                select(IdentityAccount).where(IdentityAccount.person_uid == person_uid)
            )
            .scalars()
            .first()
        )

    # -- step 1: SwissID --------------------------------------------------

    def begin_login(
        self, session: Session, actor: ActorContext
    ) -> tuple[str, str]:
        """Start the authorisation code flow. Returns (redirect URL, state)."""
        request = self._provider.start()
        now = utcnow()
        flow = OidcFlow(
            uid=new_uid("ses"),
            state=request.state,
            nonce=request.nonce,
            code_verifier=request.code_verifier,
            redirect_uri=request.url,
            created_at=now,
            expires_at=now + timedelta(seconds=OIDC_FLOW_TTL_SECONDS),
            client_ip_hash=actor.client_ip_hash,
        )
        session.add(flow)
        session.flush()
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.LOGIN_STARTED,
            resource_type="oidc_flow",
            resource_uid=flow.uid,
            detail={},
        )
        return request.url, request.state

    def complete_login(
        self, session: Session, actor: ActorContext, *, state: str, code: str
    ) -> LoginChallenge:
        """Finish SwissID, then issue the email OTP challenge."""
        flow = (
            session.execute(select(OidcFlow).where(OidcFlow.state == state))
            .scalars()
            .first()
        )
        now = utcnow()
        if flow is None or flow.consumed_at is not None or now >= flow.expires_at:
            self._fail(session, actor, "authorisation flow is unknown or expired")
        # Consume before exchanging, so a concurrent replay of the same
        # callback loses the race rather than getting a second session.
        flow.consumed_at = now
        session.flush()

        try:
            identity = self._provider.complete(
                code=code, code_verifier=flow.code_verifier, nonce=flow.nonce
            )
        except OidcError as exc:
            self._fail(session, actor, f"identity provider rejected the code: {exc}")

        account = self._resolve_account(session, identity)
        if account is None:
            # Deliberately indistinguishable from a bad code: a probe must not
            # learn whether a given SwissID is enrolled here.
            self._fail(session, actor, "no account is linked to this identity")
        if account.status != AccountStatus.ACTIVE.value:
            self._fail(session, actor, f"account is {account.status}")
        if account.locked_until is not None and now < _aware(account.locked_until):
            self._fail(session, actor, "account is temporarily locked")

        auth_session = AuthSession(
            uid=new_uid("ses"),
            account_uid=account.uid,
            person_uid=account.person_uid,
            state=SessionState.PENDING_MFA.value,
            assurance_level=AssuranceLevel.AAL1.value,
            auth_methods=["swissid"],
            expires_at=now + timedelta(seconds=OIDC_FLOW_TTL_SECONDS),
            client_ip_hash=actor.client_ip_hash,
            user_agent=(actor.user_agent or None) and actor.user_agent[:200],
        )
        session.add(auth_session)
        session.flush()

        challenge = self._issue_otp(session, actor, auth_session, account)
        self._ledger.append(
            session,
            actor=ActorContext(
                actor_uid=account.person_uid,
                actor_kind="person",
                request_id=actor.request_id,
                client_ip_hash=actor.client_ip_hash,
            ),
            action=AuditAction.MFA_CHALLENGED,
            resource_type="auth_session",
            resource_uid=auth_session.uid,
            detail={"channel": "email", "idp_acr": identity.acr},
        )
        return challenge

    def _resolve_account(
        self, session: Session, identity: VerifiedIdentity
    ) -> IdentityAccount | None:
        return (
            session.execute(
                select(IdentityAccount).where(
                    IdentityAccount.issuer == identity.issuer,
                    IdentityAccount.subject == identity.subject,
                )
            )
            .scalars()
            .first()
        )

    # -- step 2: email OTP ------------------------------------------------

    def _issue_otp(
        self,
        session: Session,
        actor: ActorContext,
        auth_session: AuthSession,
        account: IdentityAccount,
    ) -> LoginChallenge:
        challenge_uid = new_uid("ses")
        material = self._otp.generate(challenge_uid)
        challenge = OtpChallenge(
            uid=challenge_uid,
            session_uid=auth_session.uid,
            account_uid=account.uid,
            channel="email",
            code_hash=material.code_hash,
            created_at=utcnow(),
            expires_at=material.expires_at,
            max_attempts=self._otp_max_attempts,
        )
        session.add(challenge)
        session.flush()

        address = self._identity.open_field(account.uid, "email", account.email_enc)
        self._otp.deliver(
            to=address,
            code=material.code,
            expires_in_seconds=int(
                (material.expires_at - utcnow()).total_seconds()
            ),
        )
        challenge.delivered = True
        session.flush()
        return LoginChallenge(
            session_uid=auth_session.uid,
            masked_email=mask_email(address),
            expires_at=material.expires_at,
            attempts_remaining=self._otp_max_attempts,
        )

    def verify_otp(
        self, session: Session, actor: ActorContext, *, session_uid: str, code: str
    ) -> SessionTokens:
        auth_session = session.get(AuthSession, session_uid)
        now = utcnow()
        if auth_session is None or auth_session.state != SessionState.PENDING_MFA.value:
            self._fail(session, actor, "no pending second factor for this session")
        if now >= _aware(auth_session.expires_at):
            auth_session.state = SessionState.EXPIRED.value
            self._fail(session, actor, "session expired before the code was entered")

        challenge = (
            session.execute(
                select(OtpChallenge)
                .where(
                    OtpChallenge.session_uid == session_uid,
                    OtpChallenge.consumed_at.is_(None),
                )
                .order_by(OtpChallenge.created_at.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if challenge is None or now >= _aware(challenge.expires_at):
            self._fail(session, actor, "no live challenge")

        if challenge.attempts >= challenge.max_attempts:
            auth_session.state = SessionState.REVOKED.value
            self._fail(session, actor, "too many attempts")

        challenge.attempts += 1
        session.flush()

        if not self._otp.verify_code(challenge.uid, code, challenge.code_hash):
            account = session.get(IdentityAccount, challenge.account_uid)
            if account is not None:
                account.failed_attempts += 1
                if account.failed_attempts >= self._max_failed_logins:
                    # Lock rather than throttle: a health record is worth more
                    # than the inconvenience of a support call.
                    account.locked_until = now + timedelta(minutes=30)
            self._ledger.append(
                session,
                actor=actor,
                action=AuditAction.MFA_FAILED,
                resource_type="auth_session",
                resource_uid=session_uid,
                outcome=AuditOutcome.DENIED,
                detail={"attempts": challenge.attempts},
            )
            # The incremented counters are the whole point of the cap; they
            # must outlive the rollback that this exception triggers.
            commit_security_event(session)
            raise AuthError("invalid or expired code")

        challenge.consumed_at = now
        auth_session.state = SessionState.ACTIVE.value
        auth_session.assurance_level = AssuranceLevel.AAL2.value
        auth_session.auth_methods = [*auth_session.auth_methods, "otp-email"]
        auth_session.activated_at = now
        auth_session.expires_at = now + timedelta(seconds=self._refresh_ttl)

        account = session.get(IdentityAccount, challenge.account_uid)
        if account is not None:
            account.failed_attempts = 0
            account.locked_until = None
            account.last_login_at = now
            account.email_verified = True

        self._ledger.append(
            session,
            actor=ActorContext(
                actor_uid=auth_session.person_uid,
                actor_kind="person",
                request_id=actor.request_id,
                client_ip_hash=actor.client_ip_hash,
            ),
            action=AuditAction.MFA_SUCCEEDED,
            resource_type="auth_session",
            resource_uid=session_uid,
            detail={},
        )
        tokens = self._mint_session_tokens(session, auth_session)
        self._ledger.append(
            session,
            actor=ActorContext(
                actor_uid=auth_session.person_uid,
                actor_kind="person",
                request_id=actor.request_id,
                client_ip_hash=actor.client_ip_hash,
            ),
            action=AuditAction.LOGIN_SUCCEEDED,
            resource_type="auth_session",
            resource_uid=session_uid,
            detail={"assurance_level": auth_session.assurance_level},
        )
        return tokens

    def resend_otp(
        self, session: Session, actor: ActorContext, *, session_uid: str
    ) -> LoginChallenge:
        auth_session = session.get(AuthSession, session_uid)
        if auth_session is None or auth_session.state != SessionState.PENDING_MFA.value:
            self._fail(session, actor, "no pending second factor for this session")
        account = session.get(IdentityAccount, auth_session.account_uid)
        if account is None:
            self._fail(session, actor, "account vanished")
        # Invalidate the outstanding challenge so only the newest code works.
        for old in session.execute(
            select(OtpChallenge).where(
                OtpChallenge.session_uid == session_uid,
                OtpChallenge.consumed_at.is_(None),
            )
        ).scalars():
            old.consumed_at = utcnow()
        return self._issue_otp(session, actor, auth_session, account)

    # -- session tokens ---------------------------------------------------

    def _mint_session_tokens(
        self, session: Session, auth_session: AuthSession, *, parent_jti: str | None = None
    ) -> SessionTokens:
        person = session.get(Person, auth_session.person_uid)
        if person is None:
            raise AuthError("session references an unknown person")
        scopes = list(SESSION_SCOPES.get(PersonKind(person.kind), (Scope.PERSON_READ,)))
        now = utcnow()

        access_jti = new_uid("ses")
        access_claims = TokenClaims(
            jti=access_jti,
            kind=TokenKind.SESSION.value,
            issuer=self._tokens.issuer,
            subject_uid=person.uid,
            audience=self._tokens.audience,
            purpose="patient_access"
            if person.is_patient()
            else "administration",
            scopes=scopes,
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(seconds=self._session_ttl),
            session_uid=auth_session.uid,
            access_level="normal",
            assurance_level=auth_session.assurance_level,
            organization_uid=person.organization_uid,
        )
        access_token = self._tokens.issue(access_claims)

        refresh_jti = new_uid("ses")
        refresh_claims = TokenClaims(
            jti=refresh_jti,
            kind=TokenKind.REFRESH.value,
            issuer=self._tokens.issuer,
            subject_uid=person.uid,
            audience=self._tokens.audience,
            purpose="administration",
            scopes=[],
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(seconds=self._refresh_ttl),
            session_uid=auth_session.uid,
            assurance_level=auth_session.assurance_level,
        )
        refresh_token = self._tokens.issue(refresh_claims)

        for jti, kind, expires_at in (
            (access_jti, TokenKind.SESSION, access_claims.expires_at),
            (refresh_jti, TokenKind.REFRESH, refresh_claims.expires_at),
        ):
            session.add(
                IssuedToken(
                    jti=jti,
                    kind=kind.value,
                    subject_uid=person.uid,
                    session_uid=auth_session.uid,
                    issued_at=now,
                    expires_at=expires_at,
                    max_uses=1 if kind is TokenKind.REFRESH else 0,
                    parent_jti=parent_jti,
                    key_id=self._tokens.signing_kid,
                    algorithm=self._tokens.signing_algorithm,
                )
            )
        session.flush()
        return SessionTokens(
            session_uid=auth_session.uid,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=access_claims.expires_at,
            person_uid=person.uid,
            scopes=tuple(s.value for s in scopes),
        )

    def refresh(
        self, session: Session, actor: ActorContext, *, refresh_token: str
    ) -> SessionTokens:
        """Rotate the refresh token, detecting reuse.

        A refresh token is single-use. Presenting one that has already been
        spent is the signature of a stolen token being replayed, so the whole
        session — every token minted under it — is destroyed rather than the
        request merely being refused.
        """
        try:
            claims = self._tokens.verify(refresh_token)
        except TokenError as exc:
            self._fail(session, actor, f"refresh token rejected: {exc}")
        if claims.kind != TokenKind.REFRESH.value:
            self._fail(session, actor, "not a refresh token")

        record = session.get(IssuedToken, claims.jti)
        now = utcnow()
        if record is None:
            self._fail(session, actor, "refresh token is not registered")
        if record.revoked_at is not None or record.use_count >= 1:
            self._revoke_session_tokens(
                session, record.session_uid, reason="refresh token reuse detected"
            )
            self._ledger.append(
                session,
                actor=actor,
                action=AuditAction.TOKEN_REJECTED,
                resource_type="issued_token",
                resource_uid=claims.jti,
                outcome=AuditOutcome.DENIED,
                detail={"reason": "refresh reuse; session destroyed"},
            )
            commit_security_event(session)
            raise AuthError("session terminated")

        auth_session = session.get(AuthSession, claims.session_uid or "")
        if (
            auth_session is None
            or auth_session.state != SessionState.ACTIVE.value
            or now >= _aware(auth_session.expires_at)
        ):
            self._fail(session, actor, "session is no longer active")

        record.use_count += 1
        record.revoked_at = now
        record.revocation_reason = "rotated"
        record.last_used_at = now
        # The old access token dies with the rotation; a refresh must not
        # leave a second live credential behind.
        for sibling in session.execute(
            select(IssuedToken).where(
                IssuedToken.session_uid == auth_session.uid,
                IssuedToken.kind == TokenKind.SESSION.value,
                IssuedToken.revoked_at.is_(None),
            )
        ).scalars():
            sibling.revoked_at = now
            sibling.revocation_reason = "rotated"
        session.flush()
        return self._mint_session_tokens(session, auth_session, parent_jti=claims.jti)

    def logout(
        self, session: Session, actor: ActorContext, *, session_uid: str
    ) -> None:
        auth_session = session.get(AuthSession, session_uid)
        if auth_session is None:
            return
        auth_session.state = SessionState.REVOKED.value
        auth_session.revoked_at = utcnow()
        self._revoke_session_tokens(session, session_uid, reason="logout")
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.LOGOUT,
            resource_type="auth_session",
            resource_uid=session_uid,
            detail={},
        )
        session.flush()

    @staticmethod
    def _revoke_session_tokens(
        session: Session, session_uid: str | None, *, reason: str
    ) -> None:
        if not session_uid:
            return
        now = utcnow()
        for token in session.execute(
            select(IssuedToken).where(
                IssuedToken.session_uid == session_uid,
                IssuedToken.revoked_at.is_(None),
            )
        ).scalars():
            token.revoked_at = now
            token.revocation_reason = reason[:120]
        auth_session = session.get(AuthSession, session_uid)
        if auth_session is not None and auth_session.state == SessionState.ACTIVE.value:
            auth_session.state = SessionState.REVOKED.value
            auth_session.revoked_at = now
        session.flush()

    # -- verification for request handling --------------------------------

    def verify_session_token(
        self, session: Session, token: str
    ) -> tuple[TokenClaims, AuthSession]:
        """Check a session access token and that its session is still alive."""
        try:
            claims = self._tokens.verify(token)
        except TokenError as exc:
            raise AuthError(str(exc)) from exc
        if claims.kind != TokenKind.SESSION.value:
            raise AuthError("not a session token")
        record = session.get(IssuedToken, claims.jti)
        now = utcnow()
        if record is None or not record.is_live(now):
            raise AuthError("token is not live")
        auth_session = session.get(AuthSession, claims.session_uid or "")
        if (
            auth_session is None
            or auth_session.state != SessionState.ACTIVE.value
            or now >= _aware(auth_session.expires_at)
        ):
            raise AuthError("session is not active")
        if auth_session.assurance_level == AssuranceLevel.AAL1.value:
            raise AuthError("second factor required")
        record.last_used_at = now
        return claims, auth_session

    # -- helpers ----------------------------------------------------------

    def _fail(self, session: Session, actor: ActorContext, reason: str) -> NoReturn:
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.LOGIN_FAILED,
            resource_type="auth_session",
            outcome=AuditOutcome.DENIED,
            detail={"reason": reason[:200]},
        )
        commit_security_event(session)
        # One generic message for every failure mode, so the response cannot
        # be used to enumerate accounts or probe lock state.
        raise AuthError("authentication failed")


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value
