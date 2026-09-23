# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
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

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base
from ehealth.models.base import JsonType, UidPk, UtcDateTime


class AuditAction(StrEnum):
    """Closed vocabulary; free-text actions would make the trail unqueryable."""

    PERSON_REGISTERED = "person.registered"
    PERSON_UPDATED = "person.updated"
    PERSON_MERGED = "person.merged"
    #: IHE PIXm (ITI-83): identifiers of one patient across domains.
    PATIENT_CROSS_REFERENCED = "patient.cross_referenced"
    #: IHE PDQm (ITI-78): a patient search or read by another system.
    PATIENT_SEARCHED = "patient.searched"
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
        # Sequence is per chain, not global: that is what lets two clinicians
        # writing to two different patients avoid contending for one lock.
        UniqueConstraint("chain_id", "seq", name="uq_audit_event_chain_seq"),
        Index("ix_audit_chain_seq", "chain_id", "seq"),
        Index("ix_audit_dossier_ts", "dossier_uid", "occurred_at"),
        Index("ix_audit_actor_ts", "actor_uid", "occurred_at"),
        Index("ix_audit_action_ts", "action", "occurred_at"),
        Index("ix_audit_resource", "resource_type", "resource_uid"),
    )

    #: Which chain this entry belongs to: a dossier UID, or "global" for
    #: everything not scoped to one patient.
    chain_id: Mapped[str] = mapped_column(String(32), nullable=False)
    #: Position within that chain, starting at 1.
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

    #: Layout of the signed payload. Verification picks its builder by this
    #: number, so an entry written under an older format stays verifiable
    #: forever instead of silently failing once the format moves on.
    payload_version: Mapped[int] = mapped_column(Integer, nullable=False)
    #: Which build wrote this entry, e.g. ``0.1.0+g1a2b3c4``. Signed along
    #: with everything else, so "which code version produced this record" is
    #: answerable years later and cannot be edited after the fact.
    software_version: Mapped[str] = mapped_column(String(40), nullable=False)

    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(48), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(24), nullable=False)


class LedgerAnchor(Base, UidPk):
    """Periodic seal over every chain that moved, as one Merkle root.

    Publishing (or externally timestamping) the anchor bounds how far back an
    attacker who compromises the signing key could rewrite: everything before
    the last published anchor is frozen. Anchors link to their predecessor, so
    they form their own chain and a gap in them is visible too.
    """

    __tablename__ = "ledger_anchor"
    __table_args__ = (
        UniqueConstraint("period", name="uq_ledger_anchor_period"),
        Index("ix_ledger_anchor_created", "created_at"),
    )

    #: e.g. "2026-08-07" for a daily anchor.
    period: Mapped[str] = mapped_column(String(24), nullable=False)
    #: Links anchors into their own chain.
    previous_anchor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Root over the per-chain checkpoints in :class:`LedgerAnchorChain`.
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
    #: What is signed and what gets published.
    anchor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_count: Mapped[int] = mapped_column(Integer, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    key_id: Mapped[str] = mapped_column(String(48), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(24), nullable=False)
    #: Build that sealed the period, so an anchor published externally can be
    #: tied to the exact code that produced it.
    software_version: Mapped[str] = mapped_column(String(40), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, nullable=False)
    #: Reference to an external timestamp authority or notarisation, if used.
    external_reference: Mapped[str | None] = mapped_column(String(300))


class LedgerAnchorChain(Base, UidPk):
    """One chain's committed position at the moment of an anchor.

    Rows are written only for chains that *moved* in the period, so the cost
    tracks activity rather than population — the difference between an anchor
    that is affordable nationally and one that is not.
    """

    __tablename__ = "ledger_anchor_chain"
    __table_args__ = (
        UniqueConstraint("anchor_uid", "chain_id", name="uq_anchor_chain"),
        Index("ix_anchor_chain_chain", "chain_id", "last_seq"),
    )

    anchor_uid: Mapped[str] = mapped_column(
        ForeignKey("ledger_anchor.uid", ondelete="RESTRICT"), nullable=False
    )
    chain_id: Mapped[str] = mapped_column(String(32), nullable=False)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Entries added to this chain since the previous anchor.
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)


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
