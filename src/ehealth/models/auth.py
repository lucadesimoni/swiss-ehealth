# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Accounts, OIDC flows, login sessions and second-factor challenges."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import JsonType, TimestampMixin, UidPk, UtcDateTime


class AssuranceLevel(StrEnum):
    """Authenticator assurance, in the NIST SP 800-63B sense.

    SwissID at a verified level plus a second factor puts an interactive
    session at AAL2, which is the floor for touching health data here.
    """

    AAL1 = "aal1"
    AAL2 = "aal2"
    AAL3 = "aal3"


class AccountStatus(StrEnum):
    ACTIVE = "active"
    LOCKED = "locked"
    DISABLED = "disabled"


class IdentityAccount(Base, TimestampMixin, UidPk):
    """A login identity, linked to exactly one person.

    The federated subject from SwissID is the account key; no password is
    stored here at all, because there is none — authentication is delegated,
    and the second factor is a one-time code we mint ourselves.
    """

    __tablename__ = "identity_account"
    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_account_issuer_subject"),
        UniqueConstraint("person_uid", name="uq_account_person_uid"),
        Index("ix_account_email_index", "email_index"),
    )

    person_uid: Mapped[str] = mapped_column(
        ForeignKey("person.uid", ondelete="RESTRICT"), nullable=False
    )
    issuer: Mapped[str] = mapped_column(String(200), nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    #: AEAD envelope; the address itself is a direct identifier.
    email_enc: Mapped[str] = mapped_column(String(512), nullable=False)
    #: Blind index so "which account owns this address" stays answerable.
    email_index: Mapped[str] = mapped_column(String(80), nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AccountStatus.ACTIVE.value
    )
    #: Level of assurance asserted by the identity provider (e.g. QES-verified).
    idp_assurance: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AssuranceLevel.AAL1.value
    )
    mfa_required: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(UtcDateTime)


class OidcFlow(Base, UidPk):
    """Server-side state for one authorisation code flow.

    Holds the PKCE verifier and the nonce so neither has to be trusted to the
    browser, and is single-use: consuming it marks it consumed, which turns a
    replayed callback into a hard failure.
    """

    __tablename__ = "oidc_flow"
    __table_args__ = (
        UniqueConstraint("state", name="uq_oidc_flow_state"),
        Index("ix_oidc_flow_expires", "expires_at"),
    )

    state: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    code_verifier: Mapped[str] = mapped_column(String(256), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    client_ip_hash: Mapped[str | None] = mapped_column(String(64))


class SessionState(StrEnum):
    #: Identity proven, second factor still outstanding. Carries no authority.
    PENDING_MFA = "pending_mfa"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuthSession(Base, TimestampMixin, UidPk):
    __tablename__ = "auth_session"
    __table_args__ = (
        Index("ix_session_account_state", "account_uid", "state"),
        Index("ix_session_expires", "expires_at"),
    )

    account_uid: Mapped[str] = mapped_column(
        ForeignKey("identity_account.uid", ondelete="CASCADE"), nullable=False
    )
    person_uid: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default=SessionState.PENDING_MFA.value
    )
    assurance_level: Mapped[str] = mapped_column(
        String(16), nullable=False, default=AssuranceLevel.AAL1.value
    )
    #: Which methods were actually used, for the audit trail and for
    #: step-up decisions later in the session.
    auth_methods: Mapped[list] = mapped_column(JsonType, nullable=False, default=list)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    client_ip_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))


class OtpChallenge(Base, UidPk):
    """A single emailed one-time code.

    Only a keyed hash of the code is stored, attempts are counted and capped,
    and consumption is one-shot — so a challenge is worthless to anyone who
    reads the database, and brute force runs out of attempts long before it
    runs out of codes.
    """

    __tablename__ = "otp_challenge"
    __table_args__ = (Index("ix_otp_session_created", "session_uid", "created_at"),)

    session_uid: Mapped[str] = mapped_column(
        ForeignKey("auth_session.uid", ondelete="CASCADE"), nullable=False
    )
    account_uid: Mapped[str] = mapped_column(String(32), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False, default="email")
    code_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(UtcDateTime)
    #: Delivery destination is already on the account; recording only the
    #: channel here keeps the address out of a second table.
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
