"""Consent, access grants and issued tokens.

Consent is the patient's standing policy; a grant is a concrete, bounded
permission derived from it; a token is one bearer credential minted against a
grant. Keeping the three separate is what lets a patient revoke a visitor's
access instantly without touching their overall policy.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import (
    Confidentiality,
    JsonType,
    TimestampMixin,
    UidPk,
    UtcDateTime,
    VersionMixin,
)


class ParticipationStatus(StrEnum):
    """EPD participation is opt-in and revocable at any time (EPDG art. 3)."""

    ACTIVE = "active"
    WITHDRAWN = "withdrawn"
    SUSPENDED = "suspended"


class Consent(Base, TimestampMixin, VersionMixin, UidPk):
    __tablename__ = "consent"
    __table_args__ = (UniqueConstraint("patient_uid", name="uq_consent_patient_uid"),)

    patient_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    participation: Mapped[str] = mapped_column(
        String(16), nullable=False, default=ParticipationStatus.ACTIVE.value
    )
    #: Highest level a professional may reach without an explicit rule.
    default_access_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidentiality.NORMAL.value
    )
    #: Break-glass. Always audited, notifies the patient, never silent.
    emergency_access_allowed: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    #: Patient wants a notification for every access, not just emergencies.
    notify_on_access: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    withdrawn_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    #: Evidence of how consent was captured (signed form, SwissID session...).
    evidence: Mapped[dict] = mapped_column(JsonType, nullable=False, default=dict)


class RuleEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ConsentRule(Base, TimestampMixin, VersionMixin, UidPk):
    """A per-subject exception to the default policy.

    ``DENY`` always wins over ``ALLOW`` regardless of specificity — a patient's
    exclusion of a specific professional must never be overridden by a broader
    permission.
    """

    __tablename__ = "consent_rule"
    __table_args__ = (Index("ix_consent_rule_consent", "consent_uid", "effect"),)

    consent_uid: Mapped[str] = mapped_column(
        ForeignKey("consent.uid", ondelete="CASCADE"), nullable=False
    )
    #: "person" (a specific professional), "organization", or "group".
    subject_type: Mapped[str] = mapped_column(String(24), nullable=False)
    subject_uid: Mapped[str] = mapped_column(String(64), nullable=False)
    effect: Mapped[str] = mapped_column(String(8), nullable=False)
    access_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidentiality.NORMAL.value
    )
    valid_from: Mapped[datetime | None] = mapped_column(UtcDateTime)
    valid_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    note: Mapped[str | None] = mapped_column(Text)


class GrantStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AccessGrant(Base, TimestampMixin, VersionMixin, UidPk):
    """A bounded permission for one grantee on one dossier.

    Visitor access is modelled here too: a visitor is a person with a UID, and
    their access is a grant with a short validity, a narrow scope and, usually,
    a ``max_uses`` of a handful.
    """

    __tablename__ = "access_grant"
    __table_args__ = (
        Index("ix_grant_dossier_status", "dossier_uid", "status"),
        Index("ix_grant_grantee_status", "grantee_uid", "status"),
    )

    dossier_uid: Mapped[str] = mapped_column(
        ForeignKey("dossier.uid", ondelete="RESTRICT"), nullable=False
    )
    grantee_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    grantee_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    granted_by_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    access_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidentiality.NORMAL.value
    )
    #: Explicit scope strings, e.g. ["dossier:read", "medication:read"].
    scopes: Mapped[list] = mapped_column(JsonType, nullable=False, default=list)
    valid_from: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    valid_until: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=GrantStatus.ACTIVE.value
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    revoked_by_uid: Mapped[str | None] = mapped_column(String(32))
    #: 0 means unlimited within the validity window.
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    note: Mapped[str | None] = mapped_column(Text)


class TokenKind(StrEnum):
    SESSION = "session"
    REFRESH = "refresh"
    CAPABILITY = "capability"
    VISITOR = "visitor"
    EMERGENCY = "emergency"


class IssuedToken(Base, TimestampMixin):
    """Registry of every token minted, so bearer tokens stay revocable.

    Only the token id and its binding are stored — never the token itself, and
    never anything that would let the registry reconstruct one.
    """

    __tablename__ = "issued_token"
    __table_args__ = (
        Index("ix_issued_token_subject", "subject_uid", "kind"),
        Index("ix_issued_token_expires", "expires_at"),
    )

    jti: Mapped[str] = mapped_column(String(48), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_uid: Mapped[str] = mapped_column(String(32), nullable=False)
    dossier_uid: Mapped[str | None] = mapped_column(String(32))
    grant_uid: Mapped[str | None] = mapped_column(String(32))
    session_uid: Mapped[str | None] = mapped_column(String(32))
    issued_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    revocation_reason: Mapped[str | None] = mapped_column(String(120))
    #: Thumbprint of the holder's key when the token is proof-of-possession
    #: bound; NULL for plain bearer use.
    cnf_jkt: Mapped[str | None] = mapped_column(String(64))
    max_uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    use_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    #: Refresh chains: detecting reuse of a rotated token means the chain was
    #: stolen, and the whole family is killed.
    parent_jti: Mapped[str | None] = mapped_column(String(48))
    key_id: Mapped[str] = mapped_column(String(48), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(24), nullable=False)

    def is_live(self, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        if now >= self.expires_at:
            return False
        return not (self.max_uses and self.use_count >= self.max_uses)
