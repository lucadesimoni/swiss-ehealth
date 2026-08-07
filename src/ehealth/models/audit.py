"""Tamper-evident audit ledger and per-record change history.

Two complementary structures:

* :class:`AuditEvent` — an append-only, hash-chained, signed ledger of *what
  happened*. Every read and every write of health data lands here. EPDV art.
  17 requires patients to be able to see who accessed their record; the chain
  and signature make the answer trustworthy even against an operator with
  database write access.
* :class:`RecordRevision` — the *state* history of a row: which version, which
  fields changed, who changed them, and the hash of the resulting state. Every
  revision points back at the ledger sequence number that recorded it, so the
  two structures cross-verify.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import BigInteger, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import JsonType, UidPk, UtcDateTime


class AuditAction(StrEnum):
    """Closed vocabulary; free-text actions would make the trail unqueryable."""

    PERSON_REGISTERED = "person.registered"
    PERSON_UPDATED = "person.updated"
    PERSON_MERGED = "person.merged"
    AHVN_UNSEALED = "person.ahvn_unsealed"

    DOSSIER_OPENED = "dossier.opened"
    DOSSIER_READ = "dossier.read"
    DOSSIER_UPDATED = "dossier.updated"
    DOSSIER_CLOSED = "dossier.closed"

    DOCUMENT_ADDED = "document.added"
    DOCUMENT_READ = "document.read"
    DOCUMENT_UPDATED = "document.updated"
    DOCUMENT_RETRACTED = "document.retracted"

    MEDICATION_ADDED = "medication.added"
    MEDICATION_READ = "medication.read"
    MEDICATION_UPDATED = "medication.updated"
    MEDICATION_STOPPED = "medication.stopped"
    PRODUCT_REGISTERED = "product.registered"
    PRODUCT_UPDATED = "product.updated"

    CONSENT_RECORDED = "consent.recorded"
    CONSENT_UPDATED = "consent.updated"
    CONSENT_WITHDRAWN = "consent.withdrawn"

    GRANT_ISSUED = "grant.issued"
    GRANT_REVOKED = "grant.revoked"
    TOKEN_ISSUED = "token.issued"
    TOKEN_USED = "token.used"
    TOKEN_REJECTED = "token.rejected"
    TOKEN_REVOKED = "token.revoked"

    LOGIN_STARTED = "auth.login_started"
    LOGIN_SUCCEEDED = "auth.login_succeeded"
    LOGIN_FAILED = "auth.login_failed"
    MFA_CHALLENGED = "auth.mfa_challenged"
    MFA_SUCCEEDED = "auth.mfa_succeeded"
    MFA_FAILED = "auth.mfa_failed"
    LOGOUT = "auth.logout"

    EMERGENCY_ACCESS = "access.emergency"
    ACCESS_DENIED = "access.denied"
    DATA_EXPORTED = "data.exported"
    RETENTION_APPLIED = "data.retention_applied"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class AuditEvent(Base, UidPk):
    """One immutable ledger entry.

    ``entry_hash = H(prev_hash || payload_hash)`` and the signature covers
    ``entry_hash``. Deleting or editing any row breaks every subsequent link,
    which is what makes silent tampering detectable rather than merely
    discouraged.
    """

    __tablename__ = "audit_event"
    __table_args__ = (
        UniqueConstraint("seq", name="uq_audit_event_seq"),
        Index("ix_audit_dossier_ts", "dossier_uid", "occurred_at"),
        Index("ix_audit_actor_ts", "actor_uid", "occurred_at"),
        Index("ix_audit_action_ts", "action", "occurred_at"),
        Index("ix_audit_resource", "resource_type", "resource_uid"),
    )

    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)

    actor_uid: Mapped[str | None] = mapped_column(String(32))
    actor_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Set when acting for someone else (representative, delegated visitor).
    on_behalf_of_uid: Mapped[str | None] = mapped_column(String(32))
    actor_organization_uid: Mapped[str | None] = mapped_column(String(32))

    action: Mapped[str] = mapped_column(String(48), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    purpose: Mapped[str | None] = mapped_column(String(32))
    resource_type: Mapped[str] = mapped_column(String(40), nullable=False)
    resource_uid: Mapped[str | None] = mapped_column(String(64))
    dossier_uid: Mapped[str | None] = mapped_column(String(32))
    token_jti: Mapped[str | None] = mapped_column(String(48))

    request_id: Mapped[str | None] = mapped_column(String(64))
    #: Keyed hash of the client address — enough to correlate an incident,
    #: not enough to build a movement profile.
    client_ip_hash: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(200))

    #: Structured detail. Must never contain clinical content or direct
    #: identifiers; the trail itself is not a second copy of the record.
    detail: Mapped[dict] = mapped_column(JsonType, nullable=False, default=dict)

    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(48), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(24), nullable=False)


class LedgerAnchor(Base, UidPk):
    """Periodic seal over the ledger head.

    Publishing (or externally timestamping) the anchor bounds how far back an
    attacker who compromises the signing key could rewrite: everything before
    the last published anchor is frozen.
    """

    __tablename__ = "ledger_anchor"
    __table_args__ = (UniqueConstraint("period", name="uq_ledger_anchor_period"),)

    #: e.g. "2026-08-07" for a daily anchor.
    period: Mapped[str] = mapped_column(String(24), nullable=False)
    first_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(48), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(24), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    #: Reference to an external timestamp authority or notarisation, if used.
    external_reference: Mapped[str | None] = mapped_column(String(300))


class ChangeOperation(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    STATUS_CHANGE = "status_change"
    #: Logical deletion only. Clinical rows are never physically removed
    #: before their retention period elapses.
    SOFT_DELETE = "soft_delete"
    PURGE = "purge"


class RecordRevision(Base, UidPk):
    """One version of one row.

    Bitemporal: ``valid_from``/``valid_until`` describe when the *system*
    considered this version current, while the domain's own effective dates
    live on the entity. Replaying revisions in order reconstructs any row as
    it stood at any past instant, which is what "who changed what, when" has
    to mean to be useful in a clinical dispute.
    """

    __tablename__ = "record_revision"
    __table_args__ = (
        UniqueConstraint(
            "entity_type", "entity_uid", "version", name="uq_revision_entity_version"
        ),
        Index("ix_revision_entity", "entity_type", "entity_uid", "version"),
        Index("ix_revision_changed_at", "changed_at"),
        Index("ix_revision_audit_seq", "audit_seq"),
    )

    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_uid: Mapped[str] = mapped_column(String(32), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    changed_by_uid: Mapped[str | None] = mapped_column(String(32))
    changed_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    valid_from: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(UtcDateTime)
    #: {field: {"from": ..., "to": ...}} with protected fields redacted to
    #: their hash, so the diff is reviewable without re-exposing identifiers.
    diff: Mapped[dict] = mapped_column(JsonType, nullable=False, default=dict)
    #: SHA-256 over the canonical form of the full row after the change.
    state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Ledger entry that recorded this change.
    audit_seq: Mapped[int | None] = mapped_column(BigInteger)
    reason: Mapped[str | None] = mapped_column(Text)
