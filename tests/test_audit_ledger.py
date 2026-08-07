# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The tamper-evident ledger and per-record change history."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from ehealth.db import utcnow
from ehealth.models.audit import AuditAction, AuditEvent, AuditOutcome
from ehealth.models.core import PersonStatus
from ehealth.security.crypto import GENESIS_HASH
from ehealth.services.audit import ActorContext
from ehealth.services.changelog import (
    ChangeTracker,
    diff_states,
    is_protected,
    snapshot,
)
from ehealth.services.persons import PersonRegistration
from ehealth.models.core import PersonKind

from tests.conftest import AHVN_DORA


@pytest.fixture
def ledger(container):
    return container.ledger


def append(ledger, db, actor, *, action=AuditAction.DOSSIER_READ, **kwargs):
    return ledger.append(
        db, actor=actor, action=action, resource_type="dossier", **kwargs
    )


class TestChain:
    def test_starts_from_the_genesis_hash(self, ledger, db, system_actor):
        event = append(ledger, db, system_actor)
        assert event.seq == 1
        assert event.prev_hash == GENESIS_HASH.hex()

    def test_links_each_entry_to_its_predecessor(self, ledger, db, system_actor):
        first = append(ledger, db, system_actor)
        second = append(ledger, db, system_actor)
        assert second.seq == first.seq + 1
        assert second.prev_hash == first.entry_hash

    def test_verifies_an_untouched_chain(self, ledger, db, system_actor):
        for _ in range(20):
            append(ledger, db, system_actor)
        db.commit()
        result = ledger.verify_chain(db)
        assert result.ok
        assert result.checked == 20

    def test_detects_a_modified_entry(self, ledger, db, system_actor):
        """An operator editing the trail directly in the database is exactly
        what the chain exists to catch."""
        for _ in range(5):
            append(ledger, db, system_actor)
        db.commit()

        target = db.execute(select(AuditEvent).where(AuditEvent.seq == 3)).scalars().one()
        target.actor_uid = "hcp_someone_else_entirely_aaaaa"
        db.commit()

        result = ledger.verify_chain(db)
        assert not result.ok
        assert result.first_bad_seq == 3
        assert "modified" in result.reason

    def test_detects_a_deleted_entry(self, ledger, db, system_actor):
        for _ in range(5):
            append(ledger, db, system_actor)
        db.commit()
        db.delete(db.execute(select(AuditEvent).where(AuditEvent.seq == 3)).scalars().one())
        db.commit()

        result = ledger.verify_chain(db)
        assert not result.ok
        assert result.first_bad_seq == 3

    def test_detects_a_forged_signature(self, ledger, db, system_actor):
        append(ledger, db, system_actor)
        db.commit()
        event = db.execute(select(AuditEvent).where(AuditEvent.seq == 1)).scalars().one()
        event.signature = "A" * 86
        db.commit()
        result = ledger.verify_chain(db)
        assert not result.ok
        assert "signature" in result.reason

    def test_detects_an_algorithm_downgrade(self, ledger, db, system_actor):
        append(ledger, db, system_actor)
        db.commit()
        event = db.execute(select(AuditEvent).where(AuditEvent.seq == 1)).scalars().one()
        event.algorithm = "none"
        db.commit()
        assert not ledger.verify_chain(db).ok

    def test_verifies_a_partial_range(self, ledger, db, system_actor):
        for _ in range(10):
            append(ledger, db, system_actor)
        db.commit()
        result = ledger.verify_chain(db, start_seq=5, limit=3)
        assert result.ok
        assert result.checked == 3


class TestAnchoring:
    def test_seals_the_head_and_is_idempotent(self, ledger, db, system_actor):
        for _ in range(3):
            append(ledger, db, system_actor)
        db.commit()
        anchor = ledger.anchor(db, "2026-08-07")
        again = ledger.anchor(db, "2026-08-07")
        assert anchor.uid == again.uid
        assert anchor.last_seq == 3
        assert anchor.event_count == 3

    def test_second_period_covers_only_new_events(self, ledger, db, system_actor):
        for _ in range(2):
            append(ledger, db, system_actor)
        db.commit()
        ledger.anchor(db, "2026-08-07")
        for _ in range(3):
            append(ledger, db, system_actor)
        db.commit()
        second = ledger.anchor(db, "2026-08-08")
        assert second.first_seq == 3
        assert second.last_seq == 5
        assert second.event_count == 3

    def test_refuses_to_anchor_an_empty_ledger(self, ledger, db):
        with pytest.raises(ValueError, match="empty"):
            ledger.anchor(db, "2026-08-07")


class TestAuditContent:
    def test_records_the_full_actor_context(self, ledger, db):
        actor = ActorContext(
            actor_uid="hcp_01J8Z3K7QF9M2C4V6X8B0N5RTD",
            actor_kind="person",
            on_behalf_of_uid="pat_01J8Z3K7QF9M2C4V6X8B0N5RTE",
            organization_uid="org_01J8Z3K7QF9M2C4V6X8B0N5RTF",
            purpose="treatment",
            token_jti="grt_01J8Z3K7QF9M2C4V6X8B0N5RTG",
            request_id="req-1",
        )
        event = append(ledger, db, actor, outcome=AuditOutcome.DENIED)
        assert event.on_behalf_of_uid == actor.on_behalf_of_uid
        assert event.purpose == "treatment"
        assert event.outcome == "denied"

    def test_truncates_an_overlong_user_agent(self, ledger, db):
        actor = ActorContext(
            actor_uid=None, actor_kind="anonymous", user_agent="x" * 500
        )
        assert len(append(ledger, db, actor).user_agent) == 200


class TestChangeTracking:
    def test_create_records_version_one(self, container, db, system_actor):
        person = container.persons.register(
            db,
            PersonRegistration(
                kind=PersonKind.PATIENT,
                given_name="Dora",
                family_name="Test",
                ahvn13=AHVN_DORA,
            ),
            system_actor,
        )
        history = ChangeTracker.history(db, "person", person.uid)
        assert [r.version for r in history] == [1]
        assert history[0].operation == "create"
        assert history[0].audit_seq is not None

    def test_update_increments_and_records_the_diff(
        self, container, db, system_actor, world
    ):
        person = world.patient
        container.persons.update_contact(
            db, person, system_actor, phone="+41 79 000 00 00", reason="patient request"
        )
        db.commit()
        history = ChangeTracker.history(db, "person", person.uid)
        assert [r.version for r in history] == [1, 2]
        assert person.version == 2
        assert history[1].reason == "patient request"
        assert "contact_phone_enc" in history[1].diff

    def test_a_no_op_update_writes_no_revision(
        self, container, db, system_actor, world
    ):
        """Otherwise the history fills with noise and stops being readable."""
        before = len(ChangeTracker.history(db, "person", world.patient.uid))
        container.persons.update_contact(db, world.patient, system_actor)
        db.commit()
        assert len(ChangeTracker.history(db, "person", world.patient.uid)) == before

    def test_protected_fields_are_hashed_not_copied(
        self, container, db, system_actor, world
    ):
        """A change history that stored plaintext identifiers would be a
        second, unprotected copy of the record."""
        container.persons.update_contact(
            db, world.patient, system_actor, email="new.address@example.ch"
        )
        db.commit()
        latest = ChangeTracker.history(db, "person", world.patient.uid)[-1]
        change = latest.diff["contact_email_enc"]
        assert set(change["to"]) == {"sha256"}
        assert "new.address" not in str(latest.diff)

    def test_only_one_revision_is_current_at_a_time(
        self, container, db, system_actor, world
    ):
        container.persons.update_contact(db, world.patient, system_actor, phone="+41 1")
        container.persons.update_contact(db, world.patient, system_actor, phone="+41 2")
        db.commit()
        history = ChangeTracker.history(db, "person", world.patient.uid)
        open_windows = [r for r in history if r.valid_until is None]
        assert len(open_windows) == 1
        assert open_windows[0].version == max(r.version for r in history)

    def test_version_at_returns_the_revision_in_force(
        self, container, db, system_actor, world
    ):
        first = ChangeTracker.history(db, "person", world.patient.uid)[0]
        container.persons.update_contact(db, world.patient, system_actor, phone="+41 3")
        db.commit()
        at_creation = ChangeTracker.version_at(
            db, "person", world.patient.uid, first.valid_from + timedelta(microseconds=1)
        )
        assert at_creation.version == 1
        now = ChangeTracker.version_at(db, "person", world.patient.uid, utcnow())
        assert now.version == 2

    def test_replay_reconstructs_the_tracked_state(
        self, container, db, system_actor, world
    ):
        container.persons.update_contact(
            db, world.patient, system_actor, status=PersonStatus.INACTIVE
        )
        db.commit()
        state = ChangeTracker.replay(
            ChangeTracker.history(db, "person", world.patient.uid)
        )
        assert state["status"] == PersonStatus.INACTIVE.value
        assert state["uid"] == world.patient.uid

    def test_state_hash_changes_with_the_row(self, container, db, system_actor, world):
        history_before = ChangeTracker.history(db, "person", world.patient.uid)[-1]
        container.persons.update_contact(db, world.patient, system_actor, phone="+41 4")
        db.commit()
        history_after = ChangeTracker.history(db, "person", world.patient.uid)[-1]
        assert history_before.state_hash != history_after.state_hash


class TestSnapshotHelpers:
    def test_identifies_protected_fields(self):
        assert is_protected("family_name_enc")
        assert is_protected("sealed_ahvn")
        assert is_protected("ppid")
        assert not is_protected("birth_date")

    def test_snapshot_skips_bookkeeping_columns(self, world):
        keys = snapshot(world.patient).keys()
        assert "created_at" not in keys
        assert "version" not in keys

    def test_diff_reports_only_changes(self):
        assert diff_states({"a": 1, "b": 2}, {"a": 1, "b": 3}) == {
            "b": {"from": 2, "to": 3}
        }
