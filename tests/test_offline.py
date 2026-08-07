# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Offline bundles and offline capture sync.

The property under test throughout: a bundle must be verifiable with nothing
but the public key — no database, no network, no trust in whoever handed it
over. Anything less is "downloadable", not "offline".
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest

from ehealth.db import utcnow
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.clinical import MedicationEventKind
from ehealth.security.crypto import KeyRing, b64u, canonical_json
from ehealth.security.tokens import Scope
from ehealth.services.medication import ProductInput, StatementInput
from ehealth.services.offline import (
    BUNDLE_VERSION,
    BundleVerificationError,
    OfflineBundleService,
    verify_bundle,
)
from ehealth.services.sync import (
    MAX_BATCH_ITEMS,
    OfflineCapture,
    OfflineSyncService,
    SyncError,
)


@pytest.fixture
def patient_access(container, db, system_actor, world):
    from ehealth.models.core import PersonRoleKind

    grant = container.access.issue_grant(
        db,
        system_actor,
        dossier=world.dossier,
        grantee=world.patient,
        granted_by=world.patient,
        purpose=Purpose.PATIENT_ACCESS,
        grantee_role=PersonRoleKind.PATIENT,
        scopes=[
            Scope.DOSSIER_READ,
            Scope.MEDICATION_READ,
            Scope.MEDICATION_WRITE,
        ],
        access_level=Confidentiality.SECRET,
    )
    capability = container.access.mint(db, system_actor, grant=grant)
    db.commit()
    return container.access.authorize(
        db, capability.token, required_scope=Scope.DOSSIER_READ
    )


@pytest.fixture
def with_medication(container, db, system_actor, world, patient_access):
    product = container.catalogue.register(
        db,
        system_actor,
        ProductInput(
            gtin="7601000000002",
            name="Lisinopril 10 mg",
            atc_code="C09AA03",
            swissmedic_authorisation="62536",
        ),
    )
    container.medications.record(
        db,
        patient_access,
        StatementInput(
            kind=MedicationEventKind.SELF_REPORTED,
            product_uid=product.uid,
            dosage={"frequency": "1-0-0-0"},
        ),
        recorded_by_uid=world.patient.uid,
    )
    container.medications.record(
        db,
        patient_access,
        StatementInput(
            kind=MedicationEventKind.SELF_REPORTED,
            product_text="Psychopharmakon",
            confidentiality=Confidentiality.SECRET,
        ),
        recorded_by_uid=world.patient.uid,
    )
    db.commit()
    return product


class TestEmergencyDataset:
    def test_verifies_with_only_the_public_key(
        self, container, db, world, patient_access, with_medication
    ):
        """No database, no network, no account — that is the whole point."""
        bundle = container.offline.emergency_dataset(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        db.commit()

        verified = verify_bundle(bundle, container.offline.public_key())
        assert verified.kind == "emergency"
        assert verified.is_current
        assert verified.payload["medications"][0]["name"] == "Lisinopril 10 mg"

    def test_carries_the_18_digit_spid_not_the_ahv_number(
        self, container, db, world, patient_access
    ):
        from tests.conftest import AHVN_ANNA

        bundle = container.offline.emergency_dataset(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        verified = verify_bundle(bundle, container.offline.public_key())
        assert len(verified.subject_spid) == 18
        assert AHVN_ANNA.replace(".", "") not in bundle

    def test_never_carries_restricted_material(
        self, container, db, world, patient_access, with_medication
    ):
        """A bundle leaving the system loses every access control the system
        has, so what the patient hid must not travel on a card they carry."""
        bundle = container.offline.emergency_dataset(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        assert "Psychopharmakon" not in bundle
        verified = verify_bundle(bundle, container.offline.public_key())
        names = {m["name"] for m in verified.payload["medications"]}
        assert names == {"Lisinopril 10 mg"}

    def test_is_small_enough_to_carry(
        self, container, db, world, patient_access, with_medication
    ):
        """A QR code tops out around 2-3 KB of payload; a dataset that does not
        fit on a card is not an emergency dataset."""
        bundle = container.offline.emergency_dataset(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        assert len(bundle) < 2000

    def test_names_the_ledger_head_it_was_cut_from(
        self, container, db, world, patient_access
    ):
        """The head *before* the export event, which is the state the snapshot
        actually reflects."""
        head_before = container.ledger.head(db, world.dossier.uid).entry_hash
        bundle = container.offline.emergency_dataset(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        verified = verify_bundle(bundle, container.offline.public_key())
        assert verified.ledger_head == head_before
        # The export itself then advances the chain, so the bundle is placed
        # in the history rather than floating outside it.
        assert container.ledger.head(db, world.dossier.uid).entry_hash != head_before

    def test_the_export_is_audited_with_a_digest(
        self, container, db, world, patient_access
    ):
        from sqlalchemy import select

        from ehealth.models.audit import AuditEvent

        container.offline.emergency_dataset(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        db.commit()
        event = db.execute(
            select(AuditEvent).where(AuditEvent.action == "data.exported")
        ).scalars().one()
        assert event.detail["bundle_kind"] == "emergency"
        assert len(event.detail["bundle_digest"]) == 64


class TestBundleVerification:
    @pytest.fixture
    def bundle(self, container, db, world, patient_access, with_medication):
        value = container.offline.full_bundle(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        db.commit()
        return value

    def test_rejects_a_tampered_payload(self, container, bundle):
        """The attack that matters: edit the medication list, keep the
        signature."""
        header, body, signature = bundle.split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        payload["medication_statements"] = []
        forged = f"{header}.{b64u(canonical_json(payload))}.{signature}"
        with pytest.raises(BundleVerificationError, match="signature"):
            verify_bundle(forged, container.offline.public_key())

    def test_rejects_a_foreign_signature(self, container, bundle):
        other = OfflineBundleService(
            KeyRing(b"\x99" * 32), container.ledger, issuer="https://evil.example"
        )
        with pytest.raises(BundleVerificationError, match="signature"):
            verify_bundle(bundle, other.public_key())

    def test_rejects_a_non_canonical_body(self, container, bundle):
        """A body that verifies but is not canonical would let two different
        encodings claim the same signature."""
        header, body, signature = bundle.split(".")
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        padded = json.dumps(payload, indent=2).encode()
        forged = f"{header}.{b64u(padded)}.{signature}"
        with pytest.raises(BundleVerificationError):
            verify_bundle(forged, container.offline.public_key())

    def test_rejects_an_unsupported_algorithm(self, container, bundle):
        _, body, signature = bundle.split(".")
        header = b64u(canonical_json({"alg": "none", "typ": "BUNDLE"}))
        with pytest.raises(BundleVerificationError, match="unsupported algorithm"):
            verify_bundle(f"{header}.{body}.{signature}", container.offline.public_key())

    def test_rejects_an_unknown_format_version(self, container, db, world, patient_access):
        service = container.offline
        payload = {
            "v": BUNDLE_VERSION + 99,
            "kind": "dossier",
            "issued_at": utcnow().isoformat(),
            "expires_at": (utcnow() + timedelta(days=1)).isoformat(),
        }
        with pytest.raises(BundleVerificationError, match="format version"):
            verify_bundle(service.seal(payload), service.public_key())

    @pytest.mark.parametrize("broken", ["", "a.b", "a.b.c.d", "not-a-bundle"])
    def test_rejects_structurally_broken_bundles(self, container, broken):
        with pytest.raises(BundleVerificationError):
            verify_bundle(broken, container.offline.public_key())

    def test_an_expired_bundle_is_still_authentic_but_not_current(
        self, container, db, world, patient_access
    ):
        """Hiding staleness from a paramedic would be worse than showing old
        data labelled as old."""
        bundle = container.offline.emergency_dataset(
            db,
            patient=world.patient,
            dossier=world.dossier,
            actor=patient_access.actor,
            validity=timedelta(seconds=-1),
        )
        verified = verify_bundle(bundle, container.offline.public_key())
        assert verified.is_current is False
        assert verified.age >= timedelta(0)


class TestFullBundle:
    def test_carries_every_level_for_the_patient(
        self, container, db, world, patient_access, with_medication
    ):
        bundle = container.offline.full_bundle(
            db, patient=world.patient, dossier=world.dossier, actor=patient_access.actor
        )
        verified = verify_bundle(bundle, container.offline.public_key())
        levels = {
            s["confidentiality"] for s in verified.payload["medication_statements"]
        }
        assert levels == {"normal", "secret"}

    def test_a_lower_ceiling_cuts_a_smaller_bundle(
        self, container, db, world, patient_access, with_medication
    ):
        bundle = container.offline.full_bundle(
            db,
            patient=world.patient,
            dossier=world.dossier,
            actor=patient_access.actor,
            max_level=Confidentiality.NORMAL,
        )
        verified = verify_bundle(bundle, container.offline.public_key())
        assert {
            s["confidentiality"] for s in verified.payload["medication_statements"]
        } == {"normal"}


class TestOfflineSync:
    def _capture(self, client_uid: str, **overrides) -> OfflineCapture:
        captured_at = overrides.pop("captured_at", None)
        fields = dict(
            kind=MedicationEventKind.SELF_REPORTED,
            product_text="Magnesium",
            dosage={"frequency": "0-0-1-0"},
        )
        fields.update(overrides)
        return OfflineCapture(
            client_uid=client_uid,
            captured_at=captured_at,
            statement=StatementInput(**fields),
        )

    def test_applies_a_batch(self, container, db, world, patient_access):
        report = container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1"), self._capture("cli-2")],
            recorded_by_uid=world.patient.uid,
        )
        assert report.applied == 2
        assert report.rejected == 0

    def test_a_retried_batch_does_not_duplicate(
        self, container, db, world, patient_access
    ):
        """A phone that loses signal mid-upload will send the batch again."""
        batch = [self._capture("cli-1"), self._capture("cli-2")]
        first = container.sync.apply(
            db, patient_access, batch, recorded_by_uid=world.patient.uid
        )
        db.commit()
        second = container.sync.apply(
            db, patient_access, batch, recorded_by_uid=world.patient.uid
        )
        assert first.applied == 2
        assert second.applied == 0
        assert second.duplicates == 2
        # The retry names the same rows, so the client can reconcile.
        assert [r.statement_uid for r in first.results] == [
            r.statement_uid for r in second.results
        ]

    def test_a_duplicate_within_one_batch_is_reported_not_applied_twice(
        self, container, db, world, patient_access
    ):
        report = container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1"), self._capture("cli-1")],
            recorded_by_uid=world.patient.uid,
        )
        assert report.applied == 1
        assert report.duplicates == 1

    def test_one_bad_item_does_not_block_the_batch(
        self, container, db, world, patient_access
    ):
        """All-or-nothing would mean one bad row blocks a patient's whole
        history."""
        report = container.sync.apply(
            db,
            patient_access,
            [
                self._capture("cli-1"),
                self._capture("cli-bad", kind=MedicationEventKind.PRESCRIPTION),
                self._capture("cli-3"),
            ],
            recorded_by_uid=world.patient.uid,
        )
        assert report.applied == 2
        assert report.rejected == 1
        rejected = next(r for r in report.results if r.client_uid == "cli-bad")
        assert "cannot be captured offline" in rejected.reason

    def test_a_patient_cannot_capture_a_prescription_offline(
        self, container, db, world, patient_access
    ):
        """Prescribing needs a licensed professional and a live licence check,
        neither of which can happen on a phone in a tunnel."""
        report = container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1", kind=MedicationEventKind.PRESCRIPTION)],
            recorded_by_uid=world.patient.uid,
        )
        assert report.rejected == 1

    def test_records_the_device_clock_without_trusting_it(
        self, container, db, world, patient_access
    ):
        captured = utcnow() - timedelta(hours=6)
        report = container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1", captured_at=captured)],
            recorded_by_uid=world.patient.uid,
        )
        db.commit()
        statement = container.sync.find_by_client_uid(
            db, patient_access.dossier_uid, "cli-1"
        )
        assert report.applied == 1
        assert statement.captured_offline_at is not None
        # The server's own clock still orders the record.
        assert statement.created_at > statement.captured_offline_at

    def test_rejects_a_capture_time_from_the_future(
        self, container, db, world, patient_access
    ):
        report = container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1", captured_at=utcnow() + timedelta(days=2))],
            recorded_by_uid=world.patient.uid,
        )
        assert report.rejected == 1
        assert "future" in report.results[0].reason

    def test_rejects_a_naive_capture_time(
        self, container, db, world, patient_access
    ):
        from datetime import datetime

        report = container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1", captured_at=datetime(2026, 1, 1))],
            recorded_by_uid=world.patient.uid,
        )
        assert report.rejected == 1
        assert "timezone" in report.results[0].reason

    def test_refuses_an_oversized_batch(self, container, db, world, patient_access):
        with pytest.raises(SyncError, match="at most"):
            container.sync.apply(
                db,
                patient_access,
                [self._capture(f"cli-{i}") for i in range(MAX_BATCH_ITEMS + 1)],
                recorded_by_uid=world.patient.uid,
            )

    def test_the_sync_itself_is_audited(
        self, container, db, world, patient_access
    ):
        from sqlalchemy import select

        from ehealth.models.audit import AuditEvent

        container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1")],
            recorded_by_uid=world.patient.uid,
        )
        db.commit()
        event = db.execute(
            select(AuditEvent).where(AuditEvent.resource_type == "offline_sync")
        ).scalars().one()
        assert event.detail == {
            "items": 1,
            "applied": 1,
            "duplicates": 0,
            "rejected": 0,
        }

    def test_changes_since_returns_what_the_device_missed(
        self, container, db, world, patient_access
    ):
        container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-1")],
            recorded_by_uid=world.patient.uid,
        )
        db.commit()
        watermark = utcnow()
        container.sync.apply(
            db,
            patient_access,
            [self._capture("cli-2")],
            recorded_by_uid=world.patient.uid,
        )
        db.commit()
        missed = OfflineSyncService.changes_since(
            db, patient_access.dossier_uid, watermark
        )
        assert [m.offline_client_uid for m in missed] == ["cli-2"]


class TestOfflineOverHttp:
    def test_the_public_key_needs_no_authentication(self, client):
        """A paramedic's tablet has no account here."""
        response = client.get("/v1/offline/public-key", headers={"X-Admin-Key": ""})
        assert response.status_code == 200
        assert response.json()["algorithm"] == "Ed25519"
        assert response.json()["public_key"]

    def test_a_patient_exports_and_the_bundle_verifies(
        self, client, mock_idp, outbox, registry
    ):
        from tests.conftest import login

        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        client.post("/v1/consent", headers=patient.auth_header, json={})
        capability = client.post("/v1/access/self", headers=patient.auth_header).json()
        headers = {**patient.auth_header, "X-Capability": capability["token"]}

        response = client.post("/v1/offline/emergency-dataset", headers=headers)
        assert response.status_code == 200, response.text
        body = response.json()

        public_key = client.get("/v1/offline/public-key").json()["public_key"]
        verified = verify_bundle(body["bundle"], public_key)
        assert verified.is_current
        assert verified.subject_spid == registry["patient"]["spid"]

    def test_sync_over_http_is_idempotent(
        self, client, mock_idp, outbox, registry
    ):
        from tests.conftest import login

        patient = login(
            client,
            mock_idp,
            outbox,
            person_uid=registry["patient"]["uid"],
            subject="swissid-anna",
            email="anna.muster@example.ch",
        )
        client.post("/v1/consent", headers=patient.auth_header, json={})
        capability = client.post("/v1/access/self", headers=patient.auth_header).json()
        headers = {**patient.auth_header, "X-Capability": capability["token"]}

        payload = {
            "items": [
                {
                    "client_uid": "device-01J8Z3K7QF9M",
                    "kind": "self_reported",
                    "product_text": "Magnesium",
                    "dosage": {"frequency": "0-0-1-0"},
                }
            ]
        }
        first = client.post("/v1/offline/sync", headers=headers, json=payload)
        assert first.status_code == 200, first.text
        assert first.json()["applied"] == 1

        second = client.post("/v1/offline/sync", headers=headers, json=payload)
        assert second.json()["duplicates"] == 1
        assert second.json()["applied"] == 0
