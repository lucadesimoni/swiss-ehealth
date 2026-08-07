# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Consent, grants, token issuance and the access decision itself.

The decision is deliberately a *pure function* of a consent snapshot
(:func:`evaluate_policy`), so the rules can be tested exhaustively without a
database and reviewed by someone who does not read SQLAlchemy. Everything
around it — loading the snapshot, minting tokens, recording use — is
plumbing.

Policy, in one paragraph
------------------------
A patient's participation is voluntary and revocable. Within it, the patient
sets a default access level and may add per-professional or per-institution
rules; a DENY rule always beats an ALLOW, whatever its specificity, because an
exclusion the patient made explicitly must never be undone by a broader
permission. Documents marked SECRET are reachable by the patient alone.
Emergency access exists, is capped below SECRET, requires the patient not to
have disabled it, and is always recorded and notifiable — break-glass that
leaves no trace is not break-glass, it is a backdoor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import new_uid
from ehealth.models.audit import AuditAction, AuditOutcome
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.clinical import Dossier, DossierStatus
from ehealth.models.core import Person, PersonRoleKind, PersonStatus
from ehealth.models.governance import (
    AccessGrant,
    Consent,
    ConsentRule,
    GrantStatus,
    IssuedToken,
    ParticipationStatus,
    RuleEffect,
    TokenKind,
)
from ehealth.security.tokens import (
    VISITOR_SCOPE_CEILING,
    Delegation,
    Scope,
    TokenClaims,
    TokenError,
    TokenService,
)
from ehealth.services.audit import (
    ActorContext,
    AuditLedger,
    commit_security_event,
)
from ehealth.services.changelog import ChangeTracker, snapshot

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ehealth.services.persons import PersonService


class AccessError(Exception):
    """Access was refused. Carries no detail that would help probe the record."""


class ConsentError(Exception):
    pass


# --------------------------------------------------------------------------
# The pure decision
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleSnapshot:
    subject_type: str
    subject_uid: str
    effect: RuleEffect
    access_level: Confidentiality
    valid_from: datetime | None = None
    valid_until: datetime | None = None

    def applies_to(
        self, person_uid: str, organization_uid: str | None, now: datetime
    ) -> bool:
        if self.valid_from is not None and now < self.valid_from:
            return False
        if self.valid_until is not None and now >= self.valid_until:
            return False
        if self.subject_type == "person":
            return self.subject_uid == person_uid
        if self.subject_type == "organization":
            return self.subject_uid == organization_uid
        # "group" rules match a professional group name carried on the request.
        return False


@dataclass(frozen=True, slots=True)
class ConsentSnapshot:
    patient_uid: str
    participation: ParticipationStatus
    default_access_level: Confidentiality
    emergency_access_allowed: bool
    notify_on_access: bool = False
    rules: tuple[RuleSnapshot, ...] = ()


@dataclass(frozen=True, slots=True)
class AccessDecision:
    allowed: bool
    max_level: Confidentiality
    reason: str
    #: True when the patient asked to be told about this access.
    notify_patient: bool = False
    matched_rules: tuple[str, ...] = ()


#: The ceiling emergency access may reach. SECRET is never included: the
#: patient's explicitly hidden material stays hidden even in an emergency,
#: which is the deal that makes the SECRET level trustworthy at all.
EMERGENCY_CEILING = Confidentiality.RESTRICTED


def evaluate_policy(
    consent: ConsentSnapshot,
    *,
    requester_uid: str,
    requester_roles: frozenset[PersonRoleKind],
    organization_uid: str | None,
    purpose: Purpose,
    now: datetime | None = None,
) -> AccessDecision:
    """Decide what the requester may reach in this patient's record."""
    now = now or utcnow()

    # The patient always reaches their own record, at every level, including
    # after withdrawing from the system. Withdrawal removes others' access,
    # not the patient's own.
    if requester_uid == consent.patient_uid and purpose in (
        Purpose.PATIENT_ACCESS,
        Purpose.REPRESENTATIVE,
    ):
        return AccessDecision(
            True, Confidentiality.SECRET, "patient accessing their own record"
        )

    if consent.participation is not ParticipationStatus.ACTIVE:
        return AccessDecision(
            False,
            Confidentiality.NORMAL,
            f"participation is {consent.participation.value}",
        )

    if purpose is Purpose.EMERGENCY:
        if not consent.emergency_access_allowed:
            return AccessDecision(
                False, Confidentiality.NORMAL, "patient disabled emergency access"
            )
        # Emergency bypasses the *rules*, not the ceiling, and always notifies.
        return AccessDecision(
            True,
            EMERGENCY_CEILING,
            "emergency access invoked",
            notify_patient=True,
        )

    if purpose not in (Purpose.TREATMENT, Purpose.QUALITY_ASSURANCE):
        return AccessDecision(
            False, Confidentiality.NORMAL, f"purpose {purpose.value} is not permitted"
        )

    if PersonRoleKind.HEALTHCARE_PROFESSIONAL not in requester_roles:
        # Anyone who is not acting as a healthcare professional — a visitor, a
        # relative, a researcher — needs an explicit grant rather than the
        # standing consent policy. Note this is a question about *roles held*,
        # not about who the person is: a physician who is also this patient's
        # relative still gets in as a professional.
        return AccessDecision(
            False,
            Confidentiality.NORMAL,
            "requester holds no active healthcare professional role",
        )

    applicable = [
        rule
        for rule in consent.rules
        if rule.applies_to(requester_uid, organization_uid, now)
    ]
    denials = [r for r in applicable if r.effect is RuleEffect.DENY]
    if denials:
        return AccessDecision(
            False,
            Confidentiality.NORMAL,
            "an explicit exclusion applies",
            matched_rules=tuple(f"deny:{r.subject_uid}" for r in denials),
        )

    allowances = [r for r in applicable if r.effect is RuleEffect.ALLOW]
    if allowances:
        best = max(allowances, key=lambda r: r.access_level.rank)
        level = best.access_level
        matched = tuple(f"allow:{r.subject_uid}" for r in allowances)
    else:
        level = consent.default_access_level
        matched = ()

    # SECRET is patient-only by construction; a rule that tries to grant it to
    # someone else is clamped rather than honoured.
    if level is Confidentiality.SECRET:
        level = Confidentiality.RESTRICTED

    return AccessDecision(
        True,
        level,
        "permitted by consent policy",
        notify_patient=consent.notify_on_access,
        matched_rules=matched,
    )


# --------------------------------------------------------------------------
# Consent management
# --------------------------------------------------------------------------


class ConsentService:
    def __init__(
        self,
        ledger: AuditLedger,
        tracker: ChangeTracker,
        persons: "PersonService | None" = None,
    ) -> None:
        self._ledger = ledger
        self._tracker = tracker
        self._persons = persons

    def record(
        self,
        session: Session,
        actor: ActorContext,
        *,
        patient: Person,
        default_access_level: Confidentiality = Confidentiality.NORMAL,
        emergency_access_allowed: bool = True,
        notify_on_access: bool = False,
        evidence: dict | None = None,
    ) -> Consent:
        if self._persons is not None and not self._persons.has_role(
            session, patient.uid, PersonRoleKind.PATIENT
        ):
            raise ConsentError("consent can only be recorded for a patient")
        existing = self.for_patient(session, patient.uid)
        if existing is not None:
            raise ConsentError("consent already exists; update it instead")
        consent = Consent(
            uid=new_uid("cns"),
            patient_uid=patient.uid,
            participation=ParticipationStatus.ACTIVE.value,
            default_access_level=default_access_level.value,
            emergency_access_allowed=emergency_access_allowed,
            notify_on_access=notify_on_access,
            evidence=evidence or {},
        )
        session.add(consent)
        session.flush()
        self._tracker.record_create(
            session,
            consent,
            actor=actor,
            action=AuditAction.CONSENT_RECORDED,
            detail={"patient_uid": patient.uid},
        )
        return consent

    @staticmethod
    def for_patient(session: Session, patient_uid: str) -> Consent | None:
        return (
            session.execute(select(Consent).where(Consent.patient_uid == patient_uid))
            .scalars()
            .first()
        )

    def update(
        self,
        session: Session,
        actor: ActorContext,
        consent: Consent,
        *,
        default_access_level: Confidentiality | None = None,
        emergency_access_allowed: bool | None = None,
        notify_on_access: bool | None = None,
        reason: str | None = None,
    ) -> Consent:
        before = snapshot(consent)
        if default_access_level is not None:
            consent.default_access_level = default_access_level.value
        if emergency_access_allowed is not None:
            consent.emergency_access_allowed = emergency_access_allowed
        if notify_on_access is not None:
            consent.notify_on_access = notify_on_access
        self._tracker.record_update(
            session,
            consent,
            before,
            actor=actor,
            action=AuditAction.CONSENT_UPDATED,
            reason=reason,
        )
        return consent

    def withdraw(
        self, session: Session, actor: ActorContext, consent: Consent, *, reason: str
    ) -> Consent:
        """Withdraw participation and kill every outstanding grant.

        Withdrawal that left live tokens behind would be theatre, so grant
        revocation is part of the same transaction.
        """
        before = snapshot(consent)
        consent.participation = ParticipationStatus.WITHDRAWN.value
        consent.withdrawn_at = utcnow()
        self._tracker.record_update(
            session,
            consent,
            before,
            actor=actor,
            action=AuditAction.CONSENT_WITHDRAWN,
            reason=reason,
        )
        dossier = (
            session.execute(
                select(Dossier).where(Dossier.patient_uid == consent.patient_uid)
            )
            .scalars()
            .first()
        )
        if dossier is not None:
            AccessService.revoke_all_for_dossier(
                session, self._ledger, actor, dossier.uid, reason="consent withdrawn"
            )
        return consent

    def add_rule(
        self,
        session: Session,
        actor: ActorContext,
        consent: Consent,
        *,
        subject_type: str,
        subject_uid: str,
        effect: RuleEffect,
        access_level: Confidentiality = Confidentiality.NORMAL,
        valid_until: datetime | None = None,
        note: str | None = None,
    ) -> ConsentRule:
        if subject_type not in ("person", "organization", "group"):
            raise ConsentError("subject_type must be person, organization or group")
        rule = ConsentRule(
            uid=new_uid("cns"),
            consent_uid=consent.uid,
            subject_type=subject_type,
            subject_uid=subject_uid,
            effect=effect.value,
            access_level=access_level.value,
            valid_from=utcnow(),
            valid_until=valid_until,
            note=note,
        )
        session.add(rule)
        session.flush()
        self._tracker.record_create(
            session,
            rule,
            actor=actor,
            action=AuditAction.CONSENT_UPDATED,
            detail={"consent_uid": consent.uid, "effect": effect.value},
        )
        return rule

    def snapshot_for(self, session: Session, patient_uid: str) -> ConsentSnapshot:
        """Load the consent state the decision function needs.

        A patient with no consent record has not joined: the safe default is
        no third-party access at all, not "normal access".
        """
        consent = self.for_patient(session, patient_uid)
        if consent is None:
            return ConsentSnapshot(
                patient_uid=patient_uid,
                participation=ParticipationStatus.SUSPENDED,
                default_access_level=Confidentiality.NORMAL,
                emergency_access_allowed=False,
            )
        rules = session.execute(
            select(ConsentRule).where(ConsentRule.consent_uid == consent.uid)
        ).scalars()
        return ConsentSnapshot(
            patient_uid=patient_uid,
            participation=ParticipationStatus(consent.participation),
            default_access_level=Confidentiality(consent.default_access_level),
            emergency_access_allowed=consent.emergency_access_allowed,
            notify_on_access=consent.notify_on_access,
            rules=tuple(
                RuleSnapshot(
                    subject_type=rule.subject_type,
                    subject_uid=rule.subject_uid,
                    effect=RuleEffect(rule.effect),
                    access_level=Confidentiality(rule.access_level),
                    valid_from=rule.valid_from,
                    valid_until=rule.valid_until,
                )
                for rule in rules
            ),
        )


# --------------------------------------------------------------------------
# Grants and tokens
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IssuedCapability:
    token: str
    jti: str
    grant_uid: str
    expires_at: datetime
    scopes: tuple[str, ...]
    access_level: str


@dataclass(frozen=True, slots=True)
class AuthorizedAccess:
    """Result of a successful authorisation, threaded into service calls."""

    claims: TokenClaims
    grant: AccessGrant
    dossier_uid: str
    max_level: Confidentiality
    actor: ActorContext


class AccessService:
    def __init__(
        self,
        tokens: TokenService,
        consents: ConsentService,
        ledger: AuditLedger,
        tracker: ChangeTracker,
        persons: "PersonService",
        *,
        capability_ttl_seconds: int = 600,
        visitor_ttl_seconds: int = 4 * 3600,
        emergency_ttl_seconds: int = 2 * 3600,
    ) -> None:
        self._tokens = tokens
        self._consents = consents
        self._ledger = ledger
        self._tracker = tracker
        self._persons = persons
        self._capability_ttl = capability_ttl_seconds
        self._visitor_ttl = visitor_ttl_seconds
        self._emergency_ttl = emergency_ttl_seconds

    # -- granting ---------------------------------------------------------

    def issue_grant(
        self,
        session: Session,
        actor: ActorContext,
        *,
        dossier: Dossier,
        grantee: Person,
        granted_by: Person,
        purpose: Purpose,
        scopes: list[Scope],
        grantee_role: PersonRoleKind = PersonRoleKind.HEALTHCARE_PROFESSIONAL,
        ttl_seconds: int | None = None,
        access_level: Confidentiality | None = None,
        max_uses: int = 0,
        note: str | None = None,
    ) -> AccessGrant:
        """Create a bounded permission, clamped by the patient's consent.

        The clamp matters: a grant is never allowed to exceed what the consent
        policy would have permitted anyway, so a compromised granting path
        cannot escalate beyond the patient's own settings.
        """
        if grantee.status != PersonStatus.ACTIVE.value:
            raise AccessError("grantee is not active")
        if dossier.status != DossierStatus.ACTIVE.value:
            raise AccessError("dossier is not active")

        # The grant records the *capacity* the grantee acts in. A person who
        # is both a physician and this patient's relative can hold two grants
        # with different reach, and each access says which one it used.
        if not self._persons.has_role(session, grantee.uid, grantee_role):
            raise AccessError(f"grantee holds no active {grantee_role.value} role")
        consent = self._consents.snapshot_for(session, dossier.patient_uid)

        if grantee_role is PersonRoleKind.VISITOR:
            # Visitors are authorised by the patient directly, so the policy
            # check is "is the patient participating", plus a hard scope cap.
            if consent.participation is not ParticipationStatus.ACTIVE:
                raise AccessError("patient is not participating")
            if granted_by.uid != dossier.patient_uid:
                raise AccessError("only the patient may grant visitor access")
            scopes = [s for s in scopes if s in VISITOR_SCOPE_CEILING]
            if not scopes:
                raise AccessError("no permissible scope remains for a visitor")
            ceiling = Confidentiality.NORMAL
            ttl_seconds = ttl_seconds or self._visitor_ttl
        else:
            decision = evaluate_policy(
                consent,
                requester_uid=grantee.uid,
                requester_roles=self._live_roles(session, grantee.uid),
                organization_uid=self._organization_of(session, grantee.uid),
                purpose=purpose,
            )
            if not decision.allowed:
                self._deny(session, actor, dossier.uid, decision.reason)
            ceiling = decision.max_level
            ttl_seconds = ttl_seconds or self._capability_ttl

        effective_level = ceiling
        if access_level is not None:
            effective_level = min(access_level, ceiling, key=lambda c: c.rank)

        now = utcnow()
        grant = AccessGrant(
            uid=new_uid("grt"),
            dossier_uid=dossier.uid,
            grantee_uid=grantee.uid,
            grantee_kind=grantee_role.value,
            granted_by_uid=granted_by.uid,
            purpose=purpose.value,
            access_level=effective_level.value,
            scopes=[s.value for s in scopes],
            valid_from=now,
            valid_until=now + timedelta(seconds=ttl_seconds),
            status=GrantStatus.ACTIVE.value,
            max_uses=max_uses,
            note=note,
        )
        session.add(grant)
        session.flush()
        self._tracker.record_create(
            session,
            grant,
            actor=actor,
            action=AuditAction.GRANT_ISSUED,
            dossier_uid=dossier.uid,
            detail={
                "grantee_uid": grantee.uid,
                "grantee_role": grantee_role.value,
                "purpose": purpose.value,
                "access_level": effective_level.value,
                "scopes": grant.scopes,
            },
        )
        return grant

    def revoke_grant(
        self, session: Session, actor: ActorContext, grant: AccessGrant, *, reason: str
    ) -> AccessGrant:
        before = snapshot(grant)
        grant.status = GrantStatus.REVOKED.value
        grant.revoked_at = utcnow()
        grant.revoked_by_uid = actor.actor_uid
        self._tracker.record_update(
            session,
            grant,
            before,
            actor=actor,
            action=AuditAction.GRANT_REVOKED,
            dossier_uid=grant.dossier_uid,
            reason=reason,
        )
        self._revoke_tokens_for_grant(session, actor, grant.uid, reason)
        return grant

    @staticmethod
    def revoke_all_for_dossier(
        session: Session,
        ledger: AuditLedger,
        actor: ActorContext,
        dossier_uid: str,
        *,
        reason: str,
    ) -> int:
        """Kill every live grant and token on a dossier in one step."""
        now = utcnow()
        grants = list(
            session.execute(
                select(AccessGrant).where(
                    AccessGrant.dossier_uid == dossier_uid,
                    AccessGrant.status == GrantStatus.ACTIVE.value,
                )
            ).scalars()
        )
        for grant in grants:
            grant.status = GrantStatus.REVOKED.value
            grant.revoked_at = now
            grant.revoked_by_uid = actor.actor_uid
            for token in session.execute(
                select(IssuedToken).where(
                    IssuedToken.grant_uid == grant.uid,
                    IssuedToken.revoked_at.is_(None),
                )
            ).scalars():
                token.revoked_at = now
                token.revocation_reason = reason[:120]
        if grants:
            ledger.append(
                session,
                actor=actor,
                action=AuditAction.GRANT_REVOKED,
                resource_type="dossier",
                resource_uid=dossier_uid,
                dossier_uid=dossier_uid,
                detail={"revoked_grants": len(grants), "reason": reason[:200]},
            )
        session.flush()
        return len(grants)

    def _revoke_tokens_for_grant(
        self, session: Session, actor: ActorContext, grant_uid: str, reason: str
    ) -> None:
        now = utcnow()
        for token in session.execute(
            select(IssuedToken).where(
                IssuedToken.grant_uid == grant_uid, IssuedToken.revoked_at.is_(None)
            )
        ).scalars():
            token.revoked_at = now
            token.revocation_reason = reason[:120]
            self._ledger.append(
                session,
                actor=actor,
                action=AuditAction.TOKEN_REVOKED,
                resource_type="issued_token",
                resource_uid=token.jti,
                detail={"reason": reason[:200]},
            )

    # -- minting ----------------------------------------------------------

    def mint(
        self,
        session: Session,
        actor: ActorContext,
        *,
        grant: AccessGrant,
        session_uid: str | None = None,
        holder_key_b64: str | None = None,
        delegation: list[Delegation] | None = None,
        ttl_seconds: int | None = None,
    ) -> IssuedCapability:
        """Mint one capability token against a live grant."""
        now = utcnow()
        if grant.status != GrantStatus.ACTIVE.value:
            raise AccessError("grant is not active")
        if now >= grant.valid_until:
            raise AccessError("grant has expired")
        if grant.max_uses and grant.use_count >= grant.max_uses:
            raise AccessError("grant is exhausted")

        kind = (
            TokenKind.VISITOR
            if grant.grantee_kind == PersonRoleKind.VISITOR.value
            else TokenKind.EMERGENCY
            if grant.purpose == Purpose.EMERGENCY.value
            else TokenKind.CAPABILITY
        )
        default_ttl = {
            TokenKind.VISITOR: self._visitor_ttl,
            TokenKind.EMERGENCY: self._emergency_ttl,
            TokenKind.CAPABILITY: self._capability_ttl,
        }[kind]
        ttl = ttl_seconds or default_ttl
        # A token can never outlive the grant behind it.
        expires_at = min(now + timedelta(seconds=ttl), grant.valid_until)

        jti = new_uid("grt")
        claims = TokenClaims(
            jti=jti,
            kind=kind.value,
            issuer=self._tokens.issuer,
            subject_uid=grant.grantee_uid,
            audience=self._tokens.audience,
            purpose=grant.purpose,
            scopes=Scope.parse_all(grant.scopes),
            issued_at=now,
            not_before=now,
            expires_at=expires_at,
            dossier_uid=grant.dossier_uid,
            grant_uid=grant.uid,
            session_uid=session_uid,
            access_level=grant.access_level,
            organization_uid=actor.organization_uid,
            on_behalf_of_uid=grant.granted_by_uid,
            delegation=delegation or [],
            cnf_jkt=(
                TokenService.thumbprint(holder_key_b64) if holder_key_b64 else None
            ),
        )
        token = self._tokens.issue(claims)

        record = IssuedToken(
            jti=jti,
            kind=kind.value,
            subject_uid=grant.grantee_uid,
            dossier_uid=grant.dossier_uid,
            grant_uid=grant.uid,
            session_uid=session_uid,
            issued_at=now,
            expires_at=expires_at,
            cnf_jkt=claims.cnf_jkt,
            max_uses=grant.max_uses,
            key_id=self._tokens.signing_kid,
            algorithm=self._tokens.signing_algorithm,
        )
        session.add(record)
        session.flush()
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.TOKEN_ISSUED,
            resource_type="issued_token",
            resource_uid=jti,
            dossier_uid=grant.dossier_uid,
            detail={
                "kind": kind.value,
                "grant_uid": grant.uid,
                "expires_at": expires_at.isoformat(),
                "holder_bound": claims.cnf_jkt is not None,
            },
        )
        return IssuedCapability(
            token=token,
            jti=jti,
            grant_uid=grant.uid,
            expires_at=expires_at,
            scopes=tuple(grant.scopes),
            access_level=grant.access_level,
        )

    # -- authorising ------------------------------------------------------

    def authorize(
        self,
        session: Session,
        token: str,
        *,
        required_scope: Scope,
        dossier_uid: str | None = None,
        holder_key_b64: str | None = None,
        request_context: ActorContext | None = None,
    ) -> AuthorizedAccess:
        """Full check: signature, registry, grant, consent, scope.

        Consent is re-evaluated *at use time* rather than trusted from
        issuance, so a patient who revokes now is protected from a token
        minted a minute ago.
        """
        base = request_context or ActorContext(actor_uid=None, actor_kind="unknown")
        try:
            claims = self._tokens.verify(token)
            TokenService.check_holder_binding(claims, holder_key_b64)
        except TokenError as exc:
            self._reject(session, base, None, str(exc))

        actor = ActorContext(
            actor_uid=claims.subject_uid,
            actor_kind="token",
            on_behalf_of_uid=claims.on_behalf_of_uid,
            organization_uid=claims.organization_uid,
            purpose=claims.purpose,
            token_jti=claims.jti,
            request_id=base.request_id,
            client_ip_hash=base.client_ip_hash,
            user_agent=base.user_agent,
        )

        now = utcnow()
        record = session.get(IssuedToken, claims.jti)
        if record is None:
            self._reject(session, actor, claims.jti, "token is not registered")
        if not record.is_live(now):
            self._reject(session, actor, claims.jti, "token is revoked or exhausted")
        if not claims.has_scope(required_scope):
            self._reject(
                session, actor, claims.jti, f"scope {required_scope.value} missing"
            )
        if dossier_uid is not None and claims.dossier_uid != dossier_uid:
            self._reject(session, actor, claims.jti, "token is bound to another dossier")
        if claims.dossier_uid is None:
            self._reject(session, actor, claims.jti, "token names no dossier")

        grant = session.get(AccessGrant, claims.grant_uid) if claims.grant_uid else None
        if grant is None or grant.status != GrantStatus.ACTIVE.value:
            self._reject(session, actor, claims.jti, "grant is no longer active")
        if now >= grant.valid_until:
            self._reject(session, actor, claims.jti, "grant has expired")

        dossier = session.get(Dossier, claims.dossier_uid)
        if dossier is None or dossier.status != DossierStatus.ACTIVE.value:
            self._reject(session, actor, claims.jti, "dossier is not active")

        grantee = session.get(Person, claims.subject_uid)
        if grantee is None or grantee.status != PersonStatus.ACTIVE.value:
            self._reject(session, actor, claims.jti, "subject is not active")

        consent = self._consents.snapshot_for(session, dossier.patient_uid)
        purpose = Purpose(claims.purpose)
        grantee_role = PersonRoleKind(grant.grantee_kind)

        # The role the grant was issued under must still be held. A doctor
        # whose practice licence lapsed yesterday stops getting in today, even
        # with a token minted while it was valid.
        if not self._persons.has_role(session, grantee.uid, grantee_role, now=now):
            self._reject(
                session, actor, claims.jti, f"{grantee_role.value} role no longer held"
            )

        if grantee_role is PersonRoleKind.VISITOR:
            # A visitor's authority is the grant itself; consent only has to
            # still be live.
            if consent.participation is not ParticipationStatus.ACTIVE:
                self._reject(session, actor, claims.jti, "participation withdrawn")
            max_level = Confidentiality.NORMAL
        else:
            decision = evaluate_policy(
                consent,
                requester_uid=grantee.uid,
                requester_roles=self._live_roles(session, grantee.uid, now=now),
                organization_uid=self._organization_of(session, grantee.uid),
                purpose=purpose,
                now=now,
            )
            if not decision.allowed:
                self._reject(session, actor, claims.jti, decision.reason)
            max_level = decision.max_level

        # The effective ceiling is the lower of what the token claims and what
        # consent allows right now.
        token_level = Confidentiality(claims.access_level)
        effective = min(token_level, max_level, key=lambda c: c.rank)

        record.use_count += 1
        record.last_used_at = now
        grant.use_count += 1
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.TOKEN_USED,
            resource_type="issued_token",
            resource_uid=claims.jti,
            dossier_uid=claims.dossier_uid,
            detail={
                "scope": required_scope.value,
                "effective_level": effective.value,
                "use_count": record.use_count,
            },
        )
        if purpose is Purpose.EMERGENCY:
            self._ledger.append(
                session,
                actor=actor,
                action=AuditAction.EMERGENCY_ACCESS,
                resource_type="dossier",
                resource_uid=claims.dossier_uid,
                dossier_uid=claims.dossier_uid,
                detail={"grant_uid": grant.uid, "notify_patient": True},
            )
        session.flush()

        return AuthorizedAccess(
            claims=claims,
            grant=grant,
            dossier_uid=claims.dossier_uid,
            max_level=effective,
            actor=actor,
        )

    # -- helpers ----------------------------------------------------------

    def _live_roles(
        self, session: Session, person_uid: str, *, now: datetime | None = None
    ) -> frozenset[PersonRoleKind]:
        now = now or utcnow()
        return frozenset(
            PersonRoleKind(role.role)
            for role in self._persons.roles(session, person_uid)
            if role.is_live(now)
        )

    def _organization_of(self, session: Session, person_uid: str) -> str | None:
        """The institution the person currently practises at, if any.

        Read from the live professional credential rather than the person row,
        so an institution-scoped consent rule follows the licence.
        """
        credential = self._persons.active_credential(session, person_uid)
        return credential.organization_uid if credential else None

    def _reject(
        self, session: Session, actor: ActorContext, jti: str | None, reason: str
    ) -> NoReturn:
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.TOKEN_REJECTED,
            resource_type="issued_token",
            resource_uid=jti,
            outcome=AuditOutcome.DENIED,
            detail={"reason": reason[:200]},
        )
        commit_security_event(session)
        # The caller learns only that access was refused; the reason stays in
        # the trail so probing cannot map the record's structure.
        raise AccessError("access denied")

    def _deny(
        self, session: Session, actor: ActorContext, dossier_uid: str, reason: str
    ) -> NoReturn:
        self._ledger.append(
            session,
            actor=actor,
            action=AuditAction.ACCESS_DENIED,
            resource_type="dossier",
            resource_uid=dossier_uid,
            dossier_uid=dossier_uid,
            outcome=AuditOutcome.DENIED,
            detail={"reason": reason[:200]},
        )
        commit_security_event(session)
        raise AccessError("access denied")
