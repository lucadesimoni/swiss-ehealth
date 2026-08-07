# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Versioning, licence metadata and build provenance.

These are the checks that make the versioning policy enforceable rather than
aspirational: a release whose numbers have drifted fails here instead of
shipping.
"""

from __future__ import annotations

import pathlib
import re
import tomllib

import pytest
from sqlalchemy import select

from ehealth.models.audit import AuditAction, AuditEvent
from ehealth.services.audit import PAYLOAD_BUILDERS
from ehealth.version import (
    API_VERSION,
    AUDIT_PAYLOAD_VERSION,
    REVISION_ENV_VAR,
    SCHEMA_VERSION,
    UNKNOWN,
    ReleaseIdentity,
    __version__,
    release_identity,
    version_label,
)

REPO = pathlib.Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")


class TestVersionConsistency:
    """The three places a version number appears must never disagree."""

    def test_version_is_semver(self):
        assert SEMVER.match(__version__), __version__

    def test_pyproject_matches_the_module(self):
        pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
        assert pyproject["project"]["version"] == __version__

    def test_changelog_documents_this_version(self):
        changelog = (REPO / "CHANGELOG.md").read_text()
        assert f"## [{__version__}]" in changelog, (
            f"CHANGELOG.md has no section for {__version__}"
        )

    def test_changelog_has_an_unreleased_section(self):
        """So the next change has somewhere to go and nobody edits a released
        section after the fact."""
        assert "## [Unreleased]" in (REPO / "CHANGELOG.md").read_text()

    def test_changelog_records_the_compatibility_numbers(self):
        changelog = (REPO / "CHANGELOG.md").read_text()
        row = f"| {__version__} | {API_VERSION} | {SCHEMA_VERSION} | {AUDIT_PAYLOAD_VERSION} |"
        assert row in changelog, f"missing compatibility row: {row}"


class TestReleaseIdentity:
    def test_reports_all_four_numbers(self):
        identity = release_identity()
        assert identity.version == __version__
        assert identity.api_version == API_VERSION
        assert identity.schema_version == SCHEMA_VERSION
        assert identity.audit_payload_version == AUDIT_PAYLOAD_VERSION

    def test_label_fits_the_ledger_column(self):
        """The column is 40 characters; a truncated label would not match
        anything and would be worse than useless."""
        assert len(version_label()) <= 40

    def test_label_carries_the_revision_when_known(self):
        identity = ReleaseIdentity(
            version="1.2.3",
            revision="1a2b3c4d5e6f",
            dirty=False,
            build_timestamp=None,
            api_version="v1",
            schema_version=1,
            audit_payload_version=1,
        )
        assert identity.label == "1.2.3+g1a2b3c4"

    def test_label_flags_a_dirty_build(self):
        """A build from an uncommitted tree is not reproducible from any
        commit, and the label has to say so."""
        identity = ReleaseIdentity(
            version="1.2.3",
            revision="1a2b3c4d5e6f",
            dirty=True,
            build_timestamp=None,
            api_version="v1",
            schema_version=1,
            audit_payload_version=1,
        )
        assert identity.label.endswith(".dirty")

    def test_label_falls_back_to_the_bare_version(self):
        identity = ReleaseIdentity(
            version="1.2.3",
            revision=UNKNOWN,
            dirty=False,
            build_timestamp=None,
            api_version="v1",
            schema_version=1,
            audit_payload_version=1,
        )
        assert identity.label == "1.2.3"

    def test_the_pipeline_revision_wins(self, monkeypatch):
        monkeypatch.setenv(REVISION_ENV_VAR, "deadbeefcafe")
        release_identity.cache_clear()
        try:
            assert release_identity().revision == "deadbeefcafe"
            assert release_identity().label == f"{__version__}+gdeadbee"
        finally:
            release_identity.cache_clear()

    def test_a_pipeline_dirty_marker_is_honoured(self, monkeypatch):
        monkeypatch.setenv(REVISION_ENV_VAR, "deadbeefcafe.dirty")
        release_identity.cache_clear()
        try:
            identity = release_identity()
            assert identity.dirty is True
            assert identity.revision == "deadbeefcafe"
        finally:
            release_identity.cache_clear()


class TestLedgerCarriesTheVersion:
    def test_every_entry_records_the_build_and_payload_version(
        self, container, db, system_actor
    ):
        """Twenty years from now, "which code wrote this record" has to have an
        answer, and it has to be inside the signature."""
        container.ledger.append(
            db,
            actor=system_actor,
            action=AuditAction.DOSSIER_READ,
            resource_type="dossier",
        )
        db.commit()
        event = db.execute(select(AuditEvent)).scalars().one()
        assert event.software_version == version_label()
        assert event.payload_version == AUDIT_PAYLOAD_VERSION

    def test_the_version_is_covered_by_the_signature(
        self, container, db, system_actor
    ):
        container.ledger.append(
            db,
            actor=system_actor,
            action=AuditAction.DOSSIER_READ,
            resource_type="dossier",
        )
        db.commit()
        assert container.ledger.verify_chain(db).ok

        event = db.execute(select(AuditEvent)).scalars().one()
        event.software_version = "9.9.9+gfaked00"
        db.commit()

        result = container.ledger.verify_chain(db)
        assert not result.ok
        assert "modified" in result.reason

    def test_an_unknown_payload_version_fails_closed(
        self, container, db, system_actor
    ):
        """A build that cannot rebuild an entry's payload must report that,
        not wave the entry through as sound."""
        container.ledger.append(
            db,
            actor=system_actor,
            action=AuditAction.DOSSIER_READ,
            resource_type="dossier",
        )
        db.commit()
        event = db.execute(select(AuditEvent)).scalars().one()
        event.payload_version = 99
        db.commit()

        result = container.ledger.verify_chain(db)
        assert not result.ok
        assert "payload version 99 is unknown" in result.reason

    def test_anchors_record_the_build_too(self, container, db, system_actor):
        container.ledger.append(
            db,
            actor=system_actor,
            action=AuditAction.DOSSIER_READ,
            resource_type="dossier",
        )
        anchor = container.ledger.anchor(db, "2026-08-07")
        db.commit()
        assert anchor.software_version == version_label()

    def test_the_current_payload_version_has_a_builder(self):
        assert AUDIT_PAYLOAD_VERSION in PAYLOAD_BUILDERS

    def test_payload_v1_layout_is_frozen(self):
        """`_payload_v1` is hashed and signed. Changing its keys after release
        would make every existing entry fail verification, which is
        indistinguishable from tampering — so the shape is pinned here."""
        payload = PAYLOAD_BUILDERS[1](
            seq=1,
            uid="req_01J8Z3K7QF9M2C4V6X8B0N5RTD",
            occurred_at="2026-08-07T10:00:00+00:00",
            actor_uid=None,
            actor_kind="system",
            on_behalf_of_uid=None,
            actor_organization_uid=None,
            action="dossier.read",
            outcome="success",
            purpose=None,
            resource_type="dossier",
            resource_uid=None,
            dossier_uid=None,
            token_jti=None,
            detail={},
            software_version="0.1.0",
        )
        assert set(payload) == {
            "v",
            "seq",
            "uid",
            "occurred_at",
            "actor_uid",
            "actor_kind",
            "on_behalf_of_uid",
            "actor_organization_uid",
            "action",
            "outcome",
            "purpose",
            "resource_type",
            "resource_uid",
            "dossier_uid",
            "token_jti",
            "detail",
            "software_version",
        }
        assert payload["v"] == 1


class TestVersionEndpoint:
    def test_requires_the_admin_key(self, client):
        """Build provenance is what an auditor needs and what an attacker uses
        to pick a known vulnerability."""
        response = client.get("/v1/version", headers={"X-Admin-Key": "wrong"})
        assert response.status_code == 401

    def test_reports_the_full_identity(self, client):
        response = client.get("/v1/version")
        assert response.status_code == 200
        body = response.json()
        assert body["version"] == __version__
        assert body["api_version"] == API_VERSION
        assert body["schema_version"] == SCHEMA_VERSION
        assert body["audit_payload_version"] == AUDIT_PAYLOAD_VERSION
        assert body["label"] == version_label()
        assert body["audit_payload_versions_supported"] == sorted(PAYLOAD_BUILDERS)

    def test_reports_which_algorithms_may_still_be_issued(self, client):
        algorithms = client.get("/v1/version").json()["signature_algorithms"]
        assert algorithms["Ed25519"] == {"issuing": True, "available": True}
        assert algorithms["ML-DSA-65"]["available"] is False

    def test_health_stays_public_and_says_nothing_about_the_build(self, client):
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert "version" not in body
        assert "revision" not in body


class TestLicenceMetadata:
    SPDX = "SPDX-License-Identifier: AGPL-3.0-or-later"

    def test_the_licence_file_is_the_agpl(self):
        licence = (REPO / "LICENSE").read_text()
        assert "GNU AFFERO GENERAL PUBLIC LICENSE" in licence
        assert "Version 3, 19 November 2007" in licence
        # Section 13 is the reason this licence was chosen over the GPL.
        assert "13. Remote Network Interaction" in licence

    def test_pyproject_declares_the_same_licence(self):
        pyproject = tomllib.loads((REPO / "pyproject.toml").read_text())
        assert pyproject["project"]["license"] == "AGPL-3.0-or-later"

    @pytest.mark.parametrize("tree", ["src", "tests"])
    def test_every_source_file_carries_an_spdx_identifier(self, tree):
        """Licence metadata that is not checked rots. This is the check."""
        missing = [
            str(path.relative_to(REPO))
            for path in sorted((REPO / tree).rglob("*.py"))
            if self.SPDX not in path.read_text()
        ]
        assert not missing, f"missing SPDX header: {missing}"
