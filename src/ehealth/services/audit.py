# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The append-only, hash-chained, signed audit ledger.

Every access to and mutation of health data goes through :meth:`AuditLedger.append`.
The ledger is the one place in the system that is deliberately write-only:
there is no update or delete path, and the API layer exposes reads only.

Why the chain is partitioned
----------------------------
A single global chain is the obvious design and it does not scale past a small
deployment: every append has to read and lock the one tail row, so the whole
country's writes serialise through a single lock. At national volume that is
the ceiling, and it is reached long before the database runs out of anything
else.

So there is **one chain per dossier**, plus a ``global`` chain for everything
that is not dossier-scoped (registry changes, logins, the product catalogue).
Two clinicians writing to two different patients never contend; two writes to
the *same* patient still serialise, which is exactly the ordering that matters
clinically. Millions of independent chains would be unauditable on their own,
so :meth:`AuditLedger.anchor` periodically commits every active chain head into
one Merkle root, and the anchors themselves form a chain — giving back a single
value to publish while keeping the write path parallel.

Threat model
------------
The chain protects against *silent* tampering by anyone with database write
access, including the operator. It does not prevent an attacker with the
signing key from rewriting history wholesale — that is what anchoring is for:
once an anchor is published externally, everything up to it is frozen, because
a rewrite would have to produce a different Merkle root than the one already
outside the operator's control.
"""

from __future__ import annotations

import binascii
from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ehealth.db import utcnow
from ehealth.domain.uid import new_uid
from ehealth.models.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    LedgerAnchor,
    LedgerAnchorChain,
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
from ehealth.version import AUDIT_PAYLOAD_VERSION, version_label

#: Chain for everything that is not scoped to one patient's dossier.
GLOBAL_CHAIN = "global"


def chain_for(dossier_uid: str | None) -> str:
    """Which chain an event belongs to.

    Dossier-scoped events go to that dossier's chain, so the ordering
    guarantee is per patient — which is the only ordering a clinician can
    actually reason about — and writes for different patients never contend.
    """
    return dossier_uid or GLOBAL_CHAIN


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


# --------------------------------------------------------------------------
# Signed payload formats
# --------------------------------------------------------------------------


def _payload_v1(
    *,
    seq: int,
    uid: str,
    occurred_at: str,
    actor_uid: str | None,
    actor_kind: str,
    on_behalf_of_uid: str | None,
    actor_organization_uid: str | None,
    action: str,
    outcome: str,
    purpose: str | None,
    resource_type: str,
    resource_uid: str | None,
    dossier_uid: str | None,
    token_jti: str | None,
    detail: dict,
    software_version: str,
    chain_id: str | None = None,
) -> dict:
    """Version 1: one global chain, so no chain id in the payload.

    Kept verbatim forever so entries written under it stay verifiable.
    ``chain_id`` is accepted and ignored to keep one call signature.
    """
    del chain_id
    return {
        "v": 1,
        "seq": seq,
        "uid": uid,
        "occurred_at": occurred_at,
        "actor_uid": actor_uid,
        "actor_kind": actor_kind,
        "on_behalf_of_uid": on_behalf_of_uid,
        "actor_organization_uid": actor_organization_uid,
        "action": action,
        "outcome": outcome,
        "purpose": purpose,
        "resource_type": resource_type,
        "resource_uid": resource_uid,
        "dossier_uid": dossier_uid,
        "token_jti": token_jti,
        "detail": detail,
        "software_version": software_version,
    }


def _payload_v2(*, chain_id: str | None = None, **fields) -> dict:
    """Version 2: adds the chain id, so an entry cannot be replayed into a
    different chain and still verify."""
    payload = _payload_v1(**fields)
    payload["v"] = 2
    payload["chain_id"] = chain_id
    return payload


#: One builder per payload version, never edited in place.
#:
#: This is the whole reason the layout is versioned: changing ``_payload_v1``
#: after entries exist would change their hashes and make every one of them
#: fail verification. A new format is a new entry in this table plus a bump of
#: :data:`~ehealth.version.AUDIT_PAYLOAD_VERSION`; the old builder stays so old
#: entries keep verifying.
PAYLOAD_BUILDERS: dict[int, Callable[..., dict]] = {1: _payload_v1, 2: _payload_v2}


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


# --------------------------------------------------------------------------
# Merkle tree over chain heads
# --------------------------------------------------------------------------

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def merkle_leaf(chain_id: str, head_hash: str, last_seq: int) -> bytes:
    """One chain's checkpoint, as a Merkle leaf.

    Domain-separated from internal nodes so a leaf can never be presented as a
    subtree — the classic second-preimage attack on naive Merkle trees.
    """
    return sha256(
        _LEAF_PREFIX + canonical_json(
            {"chain_id": chain_id, "head_hash": head_hash, "last_seq": last_seq}
        )
    )


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root over an ordered list of leaves. Empty list hashes to the genesis."""
    if not leaves:
        return GENESIS_HASH
    level = list(leaves)
    while len(level) > 1:
        # An odd node is carried up unchanged rather than duplicated, which
        # avoids the CVE-2012-2459 style ambiguity where two different leaf
        # sets produce the same root.
        nxt = [
            sha256(_NODE_PREFIX + level[i] + level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None
    chain_id: str | None = None


@dataclass(frozen=True, slots=True)
class LedgerVerification:
    """Result of verifying every chain, or a sample of them."""

    ok: bool
    chains_checked: int
    events_checked: int
    failures: tuple[ChainVerification, ...] = ()


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
        """Append one entry to its chain and return it (not yet committed).

        The caller's transaction owns the commit, so an audit entry and the
        change it describes are atomic: a mutation that fails to audit does
        not happen at all.
        """
        chain_id = chain_for(dossier_uid)
        tail = self._tail(session, chain_id)
        seq = (tail.seq + 1) if tail else 1
        prev_hash = tail.entry_hash if tail else GENESIS_HASH.hex()
        occurred_at = occurred_at or utcnow()
        uid = new_uid("req")

        software_version = version_label()
        payload = PAYLOAD_BUILDERS[AUDIT_PAYLOAD_VERSION](
            seq=seq,
            uid=uid,
            occurred_at=occurred_at.isoformat(),
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
            detail=detail or {},
            software_version=software_version,
            chain_id=chain_id,
        )
        payload_hash = sha256(canonical_json(payload))
        entry_hash = hash_chain_link(bytes.fromhex(prev_hash), payload_hash)
        signer = self._signer()

        event = AuditEvent(
            uid=uid,
            chain_id=chain_id,
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
            payload_version=AUDIT_PAYLOAD_VERSION,
            software_version=software_version,
            payload_hash=payload_hash.hex(),
            prev_hash=prev_hash,
            entry_hash=entry_hash.hex(),
            signature=signer.sign(entry_hash),
            key_id=signer.kid,
            algorithm=signer.algorithm,
        )
        session.add(event)
        # Flush so the next append to the same chain in this transaction sees
        # it as tail; without it a multi-event request would fork the chain.
        session.flush()
        return event

    @staticmethod
    def _tail(session: Session, chain_id: str) -> AuditEvent | None:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.chain_id == chain_id)
            .order_by(AuditEvent.seq.desc())
            .limit(1)
        )
        if session.bind is not None and session.bind.dialect.name != "sqlite":
            # Serialise concurrent appends *to this chain* so two writers
            # cannot claim the same seq. Different chains never contend, which
            # is the whole point of partitioning. SQLite serialises writes at
            # the file level anyway.
            stmt = stmt.with_for_update()
        return session.execute(stmt).scalars().first()

    def head(self, session: Session, chain_id: str) -> AuditEvent | None:
        return self._tail(session, chain_id)

    @staticmethod
    def chain_ids(session: Session) -> list[str]:
        return list(
            session.execute(
                select(AuditEvent.chain_id).distinct().order_by(AuditEvent.chain_id)
            ).scalars()
        )

    # -- verification -----------------------------------------------------

    def recompute_payload_hash(self, event: AuditEvent) -> str | None:
        """Rebuild the signed payload under the entry's own format version.

        Returns ``None`` for a payload version this build does not know how to
        rebuild — verification then fails closed rather than reporting an
        entry as sound that it cannot actually check.
        """
        builder = PAYLOAD_BUILDERS.get(event.payload_version)
        if builder is None:
            return None
        payload = builder(
            seq=event.seq,
            uid=event.uid,
            occurred_at=event.occurred_at.isoformat(),
            actor_uid=event.actor_uid,
            actor_kind=event.actor_kind,
            on_behalf_of_uid=event.on_behalf_of_uid,
            actor_organization_uid=event.actor_organization_uid,
            action=event.action,
            outcome=event.outcome,
            purpose=event.purpose,
            resource_type=event.resource_type,
            resource_uid=event.resource_uid,
            dossier_uid=event.dossier_uid,
            token_jti=event.token_jti,
            detail=event.detail or {},
            software_version=event.software_version,
            chain_id=event.chain_id,
        )
        return sha256(canonical_json(payload)).hex()

    def verify_chain(
        self,
        session: Session,
        chain_id: str = GLOBAL_CHAIN,
        *,
        start_seq: int = 1,
        limit: int | None = None,
    ) -> ChainVerification:
        """Walk one chain and check hashes, links, sequence and signatures."""
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.chain_id == chain_id, AuditEvent.seq >= start_seq)
            .order_by(AuditEvent.seq)
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        events = list(session.execute(stmt).scalars())
        if not events:
            return ChainVerification(ok=True, checked=0, chain_id=chain_id)

        if start_seq <= 1:
            expected_prev = GENESIS_HASH.hex()
        else:
            previous = (
                session.execute(
                    select(AuditEvent).where(
                        AuditEvent.chain_id == chain_id,
                        AuditEvent.seq == start_seq - 1,
                    )
                )
                .scalars()
                .first()
            )
            if previous is None:
                return ChainVerification(
                    ok=False,
                    checked=0,
                    first_bad_seq=start_seq,
                    reason="predecessor of start_seq is missing",
                    chain_id=chain_id,
                )
            expected_prev = previous.entry_hash

        expected_seq = events[0].seq
        for index, event in enumerate(events):
            def fail(reason: str) -> ChainVerification:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=event.seq,
                    reason=reason,
                    chain_id=chain_id,
                )

            if event.seq != expected_seq:
                return ChainVerification(
                    ok=False,
                    checked=index,
                    first_bad_seq=expected_seq,
                    reason=f"sequence gap: expected {expected_seq}, found {event.seq}",
                    chain_id=chain_id,
                )
            if event.prev_hash != expected_prev:
                return fail("broken link: prev_hash does not match predecessor")

            recomputed_payload = self.recompute_payload_hash(event)
            if recomputed_payload is None:
                return fail(
                    f"payload version {event.payload_version} is unknown to this "
                    f"build; verify with a build that supports it"
                )
            if recomputed_payload != event.payload_hash:
                return fail("entry content was modified after the fact")
            try:
                recomputed = hash_chain_link(
                    bytes.fromhex(event.prev_hash), bytes.fromhex(event.payload_hash)
                ).hex()
            except (ValueError, binascii.Error):
                return fail("malformed hash encoding")
            if recomputed != event.entry_hash:
                return fail("entry hash does not match its inputs")
            if not self._verify_signature(event):
                return fail("signature does not verify")

            expected_prev = event.entry_hash
            expected_seq += 1

        return ChainVerification(
            ok=True, checked=len(events), chain_id=chain_id
        )

    def verify_all(
        self, session: Session, *, max_chains: int | None = None
    ) -> LedgerVerification:
        """Verify every chain. The honest whole-system integrity check.

        At national scale this is a background job, not a request — which is
        why :meth:`verify_chain` for a single dossier exists and is the one a
        patient's "was my record tampered with" question actually needs.
        """
        chains = self.chain_ids(session)
        if max_chains is not None:
            chains = chains[:max_chains]
        failures: list[ChainVerification] = []
        events_checked = 0
        for chain_id in chains:
            result = self.verify_chain(session, chain_id)
            events_checked += result.checked
            if not result.ok:
                failures.append(result)
        return LedgerVerification(
            ok=not failures,
            chains_checked=len(chains),
            events_checked=events_checked,
            failures=tuple(failures),
        )

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
        """Seal every chain that moved since the last anchor, into one root.

        Chains that changed in this period get a checkpoint row; the Merkle
        root over those checkpoints, together with the previous anchor's hash,
        is what gets signed and published. Anchors therefore form their own
        chain, and the number of checkpoint rows is proportional to *activity*
        rather than to population — which is what keeps this affordable
        nationally.

        Idempotent per period: sealing the same period twice returns the
        existing anchor rather than producing a second, conflicting seal.
        """
        existing = (
            session.execute(select(LedgerAnchor).where(LedgerAnchor.period == period))
            .scalars()
            .first()
        )
        if existing is not None:
            return existing

        previous = (
            session.execute(
                select(LedgerAnchor).order_by(LedgerAnchor.created_at.desc()).limit(1)
            )
            .scalars()
            .first()
        )
        previous_hash = previous.anchor_hash if previous else GENESIS_HASH.hex()

        checkpoints = self._pending_checkpoints(session, previous)
        if not checkpoints:
            raise ValueError("nothing to anchor: no chain has moved")

        leaves = [
            merkle_leaf(chain_id, head_hash, last_seq)
            for chain_id, last_seq, head_hash, _ in checkpoints
        ]
        root = merkle_root(leaves)

        anchor_uid = new_uid("req")
        signer = self._signer()
        software_version = version_label()
        body = canonical_json(
            {
                "period": period,
                "previous_anchor_hash": previous_hash,
                "merkle_root": root.hex(),
                "chain_count": len(checkpoints),
                "event_count": sum(count for *_, count in checkpoints),
                "software_version": software_version,
            }
        )
        anchor_hash = sha256(body)

        anchor = LedgerAnchor(
            uid=anchor_uid,
            period=period,
            previous_anchor_hash=previous_hash,
            merkle_root=root.hex(),
            anchor_hash=anchor_hash.hex(),
            chain_count=len(checkpoints),
            event_count=sum(count for *_, count in checkpoints),
            signature=signer.sign(anchor_hash),
            key_id=signer.kid,
            algorithm=signer.algorithm,
            software_version=software_version,
            created_at=utcnow(),
        )
        session.add(anchor)
        for chain_id, last_seq, head_hash, count in checkpoints:
            session.add(
                LedgerAnchorChain(
                    uid=new_uid("req"),
                    anchor_uid=anchor_uid,
                    chain_id=chain_id,
                    last_seq=last_seq,
                    head_hash=head_hash,
                    event_count=count,
                )
            )
        session.flush()
        return anchor

    @staticmethod
    def _pending_checkpoints(
        session: Session, previous: LedgerAnchor | None
    ) -> list[tuple[str, int, str, int]]:
        """(chain_id, last_seq, head_hash, events since the previous anchor)."""
        previous_seqs: dict[str, int] = {}
        if previous is not None:
            previous_seqs = {
                row.chain_id: row.last_seq
                for row in session.execute(
                    select(LedgerAnchorChain).where(
                        LedgerAnchorChain.anchor_uid == previous.uid
                    )
                ).scalars()
            }
            # Carry forward checkpoints from anchors older than the previous
            # one, so a chain that went quiet keeps its committed position.
            for row in session.execute(
                select(
                    LedgerAnchorChain.chain_id,
                    func.max(LedgerAnchorChain.last_seq),
                ).group_by(LedgerAnchorChain.chain_id)
            ):
                previous_seqs.setdefault(row[0], row[1])
                previous_seqs[row[0]] = max(previous_seqs[row[0]], row[1])

        heads = session.execute(
            select(
                AuditEvent.chain_id,
                func.max(AuditEvent.seq).label("last_seq"),
                func.count().label("total"),
            ).group_by(AuditEvent.chain_id)
        ).all()

        checkpoints: list[tuple[str, int, str, int]] = []
        for chain_id, last_seq, _total in heads:
            since = previous_seqs.get(chain_id, 0)
            if last_seq <= since:
                continue  # chain has not moved
            head = (
                session.execute(
                    select(AuditEvent).where(
                        AuditEvent.chain_id == chain_id, AuditEvent.seq == last_seq
                    )
                )
                .scalars()
                .one()
            )
            checkpoints.append((chain_id, last_seq, head.entry_hash, last_seq - since))
        checkpoints.sort(key=lambda row: row[0])
        return checkpoints

    def verify_anchor(self, session: Session, anchor: LedgerAnchor) -> bool:
        """Recompute an anchor's Merkle root and signature from its checkpoints.

        This is what makes a published anchor meaningful later: anyone with the
        database and the public key can confirm the value that was published
        is the value the data still produces.
        """
        checkpoints = list(
            session.execute(
                select(LedgerAnchorChain)
                .where(LedgerAnchorChain.anchor_uid == anchor.uid)
                .order_by(LedgerAnchorChain.chain_id)
            ).scalars()
        )
        root = merkle_root(
            [
                merkle_leaf(row.chain_id, row.head_hash, row.last_seq)
                for row in checkpoints
            ]
        )
        if root.hex() != anchor.merkle_root:
            return False
        body = canonical_json(
            {
                "period": anchor.period,
                "previous_anchor_hash": anchor.previous_anchor_hash,
                "merkle_root": anchor.merkle_root,
                "chain_count": anchor.chain_count,
                "event_count": anchor.event_count,
                "software_version": anchor.software_version,
            }
        )
        anchor_hash = sha256(body)
        if anchor_hash.hex() != anchor.anchor_hash:
            return False
        try:
            version = int(anchor.key_id.rsplit(".v", 1)[1])
        except (IndexError, ValueError):
            return False
        return self._signer(version).verify(anchor_hash, anchor.signature)
