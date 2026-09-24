# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Retention (EPDV art. 10): destroy health data, keep the audit trail."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from ehealth.db import get_session_factory, utcnow
from ehealth.models.audit import AuditAction, AuditEvent, RecordRevision
from ehealth.models.clinical import Dossier, DossierDocument, DossierStatus
from ehealth.services.audit import ActorContext
from tests.document_helpers import PDF, publish, published_uid

SYSTEM = ActorContext.system(request_id="test-retention")


def expire(dossier_uid: str) -> None:
    with get_session_factory()() as db:
        db.get(Dossier, dossier_uid).retention_until = utcnow() - timedelta(days=1)
        db.commit()


def run(container, *, dry_run):
    with get_session_factory()() as db:
        results = container.retention.apply(db, SYSTEM, dry_run=dry_run)
        db.commit()
    return results


class TestRetention:
    def test_nothing_is_due_before_the_horizon(self, client, headers, world, container):
        publish(client, headers, world)
        assert run(container, dry_run=False) == []

    def test_a_dry_run_changes_nothing(self, client, headers, world, container):
        uid = published_uid(publish(client, headers, world))
        expire(world.dossier.uid)
        (result,) = run(container, dry_run=True)
        assert result.documents == 1 and not result.applied
        assert client.get(f"/v1/fhir/Binary/{uid}", headers=headers).content == PDF

    def test_applying_destroys_content_titles_and_history_values(
        self, client, headers, world, container
    ):
        uid = published_uid(publish(client, headers, world, title="HIV-Befund"))
        expire(world.dossier.uid)
        (result,) = run(container, dry_run=False)
        assert result.applied

        backend = container.dossiers._content._backend
        assert uid not in backend.blobs, "the encrypted content must be gone"
        with get_session_factory()() as db:
            document = db.get(DossierDocument, uid)
            assert "HIV" not in document.title
            assert document.storage_ref is None
            assert (
                db.get(Dossier, world.dossier.uid).status
                == DossierStatus.ARCHIVED.value
            )
            revisions = db.execute(
                select(RecordRevision).where(RecordRevision.entity_uid == uid)
            ).scalars()
            assert "HIV" not in str([r.diff for r in revisions])

    def test_the_audit_trail_survives_and_still_verifies(
        self, client, headers, world, container
    ):
        """Who read the record, and when, stays answerable after the record
        itself is gone — and the chain is not touched, so it still verifies."""
        uid = published_uid(publish(client, headers, world))
        client.get(f"/v1/fhir/Binary/{uid}", headers=headers)
        expire(world.dossier.uid)
        run(container, dry_run=False)

        with get_session_factory()() as db:
            reads = db.execute(
                select(AuditEvent).where(
                    AuditEvent.action == AuditAction.DOCUMENT_READ.value,
                    AuditEvent.resource_uid == uid,
                )
            ).scalars()
            assert list(reads)
            (applied,) = db.execute(
                select(AuditEvent).where(
                    AuditEvent.action == AuditAction.RETENTION_APPLIED.value
                )
            ).scalars()
            assert applied.detail["documents"] == 1
        verify = client.get(
            "/v1/audit/verify", params={"chain_id": world.dossier.uid}
        ).json()
        assert verify["ok"], verify
        assert client.get("/v1/audit/verify").json()["ok"]

    def test_an_archived_dossier_is_not_processed_twice(
        self, client, headers, world, container
    ):
        publish(client, headers, world)
        expire(world.dossier.uid)
        run(container, dry_run=False)
        assert run(container, dry_run=False) == []

    def test_an_archived_dossier_accepts_no_new_documents(
        self, client, headers, world, container
    ):
        publish(client, headers, world)
        expire(world.dossier.uid)
        run(container, dry_run=False)
        assert publish(client, headers, world).status_code >= 400
