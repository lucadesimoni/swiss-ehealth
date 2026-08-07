"""The append-only, hash-chained, signed audit ledger.

Every access to and mutation of health data goes through :meth:`AuditLedger.append`.
The ledger is the one place in the system that is deliberately write-only:
there is no update or delete path, and the API layer exposes reads only.

Threat model
------------
The chain protects against *silent* tampering by anyone with database write
access, including the operator. It does not prevent an attacker with the
signing key from rewriting history wholesale — that is what
:meth:`AuditLedger.anchor` is for: once an anchor is published externally,
everything up to it is frozen, because a rewrite would have to produce a
different head hash than the one already outside the operator's control.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import new_uid
from ehealth.models.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    LedgerAnchor,
)
from ehealth.security.crypto import (
    GENESIS_HASH,
    KeyPurpose,
    KeyRing,
    Signer,
    canonical_json,
    hash_chain_link,
    sha256,
)


@dataclass(frozen=True, slots=True)
class ActorContext:
    """Who is acting, on whose behalf, and under what authority.

    Threaded through every service call. A ``None`` actor is only legitimate
    for system jobs, which is why ``actor_kind`` is mandatory and says so.
    """

    actor_uid: str | None
    actor_kind: str
    on_behalf_of_uid: str | None = None
    organization_uid: str | None = None
    purpose: str | None = None
    token_jti: str | None = None
    request_id: str | None = None
    client_ip_hash: str | None = None
    user_agent: str | None = None

    @classmethod
    def system(cls, request_id: str | None = None) -> "ActorContext":
        return cls(actor_uid=None, actor_kind="system", request_id=request_id)


def commit_security_event(session: Session) -> None:
    """Commit right now, before raising a denial.

    Normally a service leaves committing to the request boundary, so a failed
    operation writes nothing. Security events are the deliberate exception: a
    rejected token, a failed second factor and an incremented attempt counter
    all have to survive the rollback that follows, or the audit trail would
    record only successes and the attempt caps would never bite.

    Everything written before this point on a denial path is state we *want*
    persisted — the consumed authorisation flow, the attempt counters, the
    ledger entry — so committing here is not a partial write.
    """
    session.commit()


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


class AuditLedger:
    def __init__(self, keyring: KeyRing) -> None:
        self._keyring = keyring

    def _signer(self, version: int | None = None) -> Signer:
        return self._keyring.signer(KeyPurpose.AUDIT_LEDGER, version)

    # -- writing ----------------------------------------------------------

    def append(
        self,
        session: Session,
        *,
        actor: ActorContext,
        action: AuditAction,
        resource_type: str,
        resource_uid: str | None = None,
        dossier_uid: str | None = None,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        detail: dict | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        """Append one entry and return it (not yet committed).

        The caller's transaction owns the commit, so an audit entry and the
        change it describes are atomic: a mutation that fails to audit does
        not happen at all.
        """
        tail = self._tail(session)
        seq = (tail.seq + 1) if tail else 1
        prev_hash = tail.entry_hash if tail else GENESIS_HASH.hex()
        occurred_at = occurred_at or utcnow()
        uid = new_uid("req")

        payload = {
            "seq": seq,
            "uid": uid,
            "occurred_at": occurred_at.isoformat(),
            "actor_uid": actor.actor_uid,
            "actor_kind": actor.actor_kind,
            "on_behalf_of_uid": actor.on_behalf_of_uid,
            "actor_organization_uid": actor.organization_uid,
            "action": action.value,
            "outcome": outcome.value,
            "purpose": actor.purpose,
            "resource_type": resource_type,
            "resource_uid": resource_uid,
            "dossier_uid": dossier_uid,
            "token_jti": actor.token_jti,
            "detail": detail or {},
        }
        payload_hash = sha256(canonical_json(payload))
        entry_hash = hash_chain_link(bytes.fromhex(prev_hash), payload_hash)
        signer = self._signer()

        event = AuditEvent(
            uid=uid,
            seq=seq,
            occurred_at=occurred_at,
            actor_uid=actor.actor_uid,
            actor_kind=actor.actor_kind,
            on_behalf_of_uid=actor.on_behalf_of_uid,
            actor_organization_uid=actor.organization_uid,
            action=action.value,
            outcome=outcome.value,
            purpose=actor.purpose,
            resource_type=resource_type,
            resource_uid=resource_uid,
            dossier_uid=dossier_uid,
            token_jti=actor.token_jti,
            request_id=actor.request_id,
            client_ip_hash=actor.client_ip_hash,
            user_agent=(actor.user_agent or None) and actor.user_agent[:200],
            detail=payload["detail"],
            payload_hash=payload_hash.hex(),
            prev_hash=prev_hash,
            entry_hash=entry_hash.hex(),
            signature=signer.sign(entry_hash),
            key_id=signer.kid,
            algorithm=signer.algorithm,
        )
        session.add(event)
        # Flush so the next append in the same transaction sees this as tail;
        # without it a multi-event request would fork the chain.
        session.flush()
        return event

    @staticmethod
    def _tail(session: Session) -> AuditEvent | None:
        stmt = select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1)
        if session.bind is not None and session.bind.dialect.name != "sqlite":
            # Serialise concurrent appends so two writers cannot claim the
            # same seq. SQLite serialises writes at the file level anyway.
            stmt = stmt.with_for_update()
        return session.execute(stmt).scalars().first()

    # -- verification -----------------------------------------------------

    def recompute_payload_hash(self, event: AuditEvent) -> str:
        payload = {
            "seq": event.seq,
            "uid": event.uid,
            "occurred_at": event.occurred_at.isoformat(),
            "actor_uid": event.actor_uid,
            "actor_kind": event.actor_kind,
            "on_behalf_of_uid": event.on_behalf_of_uid,
            "actor_organization_uid": event.actor_organization_uid,
            "action": event.action,
            "outcome": event.outcome,
            "purpose": event.purpose,
            "resource_type": event.resource_type,
            "resource_uid": event.resource_uid,
            "dossier_uid": event.dossier_uid,
            "token_jti": event.token_jti,
            "detail": event.detail or {},
        }
        return sha256(canonical_json(payload)).hex()

    def verify_chain(
        self, session: Session, *, start_seq: int = 1, limit: int | None = None
    ) -> ChainVerification:
        """Walk the chain and check hashes, links, sequence and signatures."""
        stmt = select(AuditEvent).where(AuditEvent.seq >= start_seq).order_by(
            AuditEvent.seq
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        events = list(session.execute(stmt).scalars())
        if not events:
            return ChainVerification(ok=True, checked=0)

        if start_seq <= 1:
            expected_prev = GENESIS_HASH.hex()
        else:
            previous = session.execute(
                select(AuditEvent).where(AuditEvent.seq == start_seq - 1)
            ).scalars().first()
            if previous is None:
                return ChainVerification(
                    ok=False,
                    checked=0,
                    first_bad_seq=start_seq,
                    reason="predecessor of start_seq is missing",
                )
            expected_prev = previous.entry_hash

        expected_seq = events[0].seq
        for index, event in enumerate(events):
            if event.seq != expected_seq:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=expected_seq,
                    reason=f"sequence gap: expected {expected_seq}, found {event.seq}",
                )
            if event.prev_hash != expected_prev:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=event.seq,
                    reason="broken link: prev_hash does not match predecessor",
                )
            if self.recompute_payload_hash(event) != event.payload_hash:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=event.seq,
                    reason="entry content was modified after the fact",
                )
            try:
                recomputed = hash_chain_link(
                    bytes.fromhex(event.prev_hash), bytes.fromhex(event.payload_hash)
                ).hex()
            except (ValueError, binascii.Error):
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=event.seq,
                    reason="malformed hash encoding",
                )
            if recomputed != event.entry_hash:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=event.seq,
                    reason="entry hash does not match its inputs",
                )
            if not self._verify_signature(event):
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=event.seq,
                    reason="signature does not verify",
                )
            expected_prev = event.entry_hash
            expected_seq += 1

        return ChainVerification(ok=True, checked=len(events))

    def _verify_signature(self, event: AuditEvent) -> bool:
        if event.algorithm != "Ed25519":
            # Unknown algorithm: refuse rather than silently pass, so a
            # downgrade is a verification failure and not a blind spot.
            return False
        try:
            version = int(event.key_id.rsplit(".v", 1)[1])
        except (IndexError, ValueError):
            return False
        try:
            signer = self._signer(version)
        except Exception:  # noqa: BLE001 - unknown key version
            return False
        return signer.verify(bytes.fromhex(event.entry_hash), event.signature)

    # -- anchoring --------------------------------------------------------

    def anchor(self, session: Session, period: str) -> LedgerAnchor:
        """Seal the ledger head for ``period`` (e.g. ``2026-08-07``).

        Idempotent per period: sealing the same period twice returns the
        existing anchor rather than producing a second, conflicting seal.
        """
        existing = session.execute(
            select(LedgerAnchor).where(LedgerAnchor.period == period)
        ).scalars().first()
        if existing is not None:
            return existing

        tail = self._tail(session)
        if tail is None:
            raise ValueError("cannot anchor an empty ledger")
        previous = session.execute(
            select(LedgerAnchor).order_by(LedgerAnchor.last_seq.desc()).limit(1)
        ).scalars().first()
        first_seq = (previous.last_seq + 1) if previous else 1
        count = session.execute(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.seq.between(first_seq, tail.seq))
        ).scalar_one()

        signer = self._signer()
        body = canonical_json(
            {
                "period": period,
                "first_seq": first_seq,
                "last_seq": tail.seq,
                "head_hash": tail.entry_hash,
                "event_count": count,
            }
        )
        anchor = LedgerAnchor(
            uid=new_uid("req"),
            period=period,
            first_seq=first_seq,
            last_seq=tail.seq,
            head_hash=tail.entry_hash,
            event_count=count,
            signature=signer.sign(sha256(body)),
            key_id=signer.kid,
            algorithm=signer.algorithm,
            created_at=utcnow(),
        )
        session.add(anchor)
        session.flush()
        return anchor
