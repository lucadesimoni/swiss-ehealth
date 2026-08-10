# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The release ledger, checked against the repository it describes.

The test that earns its keep is
:meth:`TestLedgerMatchesTheRepository.test_every_entry_matches_its_commit`. A
manifest that merely parses proves nothing — anyone can write a plausible SHA.
This reads ``src/ehealth/version.py`` *at each recorded commit* and requires it
to declare exactly the numbers the entry claims, so an invented, mistyped or
stale SHA fails here rather than misleading an auditor years later.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess

import pytest

from ehealth.releases import (
    MANIFEST_NAME,
    MANIFEST_VERSION,
    ManifestError,
    Release,
    find_release,
    latest_release,
    load_manifest,
    parse_manifest,
    render_manifest,
    version_key,
)
from ehealth.version import (
    API_VERSION,
    AUDIT_PAYLOAD_VERSION,
    SCHEMA_VERSION,
    __version__,
)

REPO = pathlib.Path(__file__).resolve().parents[1]


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=False
    )


def declared_at(commit: str, name: str) -> str | None:
    """Read one module-level constant out of ``version.py`` at a past commit.

    Textual on purpose: importing a twenty-year-old module to ask what it
    declares would run that code, and the assignment is the fact being
    checked.
    """
    shown = git("show", f"{commit}:src/ehealth/version.py")
    if shown.returncode != 0:
        return None
    match = re.search(rf"^{name}\s*=\s*(.+)$", shown.stdout, re.MULTILINE)
    return match.group(1).strip().strip('"') if match else None


@pytest.fixture(scope="session")
def repository_history_available() -> bool:
    """Skip the history checks where the history is not there to check.

    A shallow clone — the CI default — genuinely cannot resolve older release
    commits. Skipping is honest; passing would not be.
    """
    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    if git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        pytest.skip("shallow clone: release commits are not present to verify")
    return True


class TestLedgerMatchesTheRepository:
    def test_every_entry_matches_its_commit(self, repository_history_available):
        """The check a fabricated entry cannot survive."""
        for release in load_manifest():
            resolved = git("rev-parse", "--verify", f"{release.commit}^{{commit}}")
            assert resolved.returncode == 0, (
                f"{MANIFEST_NAME} records commit {release.commit} for "
                f"{release.version}, which is not in this repository"
            )

            for name, claimed in (
                ("__version__", release.version),
                ("API_VERSION", release.api_version),
                ("SCHEMA_VERSION", str(release.schema_version)),
                ("AUDIT_PAYLOAD_VERSION", str(release.audit_payload_version)),
            ):
                found = declared_at(release.commit, name)
                assert found == claimed, (
                    f"{MANIFEST_NAME} claims {release.version} has "
                    f"{name} = {claimed}, but commit {release.short_commit} "
                    f"declares {found}"
                )

    def test_recorded_dates_are_the_commit_dates(self, repository_history_available):
        for release in load_manifest():
            committed = git(
                "show", "-s", "--format=%cd", "--date=format:%Y-%m-%d", release.commit
            ).stdout.strip()
            assert release.date == committed, (
                f"{release.version} is dated {release.date} but its commit "
                f"was made on {committed}"
            )

    def test_tags_agree_with_the_ledger_where_they_exist(
        self, repository_history_available
    ):
        """Tags are the convenient handle, the ledger is the durable one, and
        a disagreement between them means one of the two is lying."""
        for release in load_manifest():
            resolved = git("rev-list", "-n1", release.tag)
            if resolved.returncode != 0:
                continue  # tag absent here — the ledger still stands alone
            assert resolved.stdout.strip() == release.commit, (
                f"tag {release.tag} points at {resolved.stdout.strip()[:7]} but "
                f"{MANIFEST_NAME} records {release.short_commit}. A published "
                f"tag is never moved; fix the tag, not the ledger."
            )

    def test_releases_are_ancestors_of_this_commit(self, repository_history_available):
        """A release that is not in this branch's history was cut from
        somewhere else, and the ledger would be describing another line of
        development."""
        for release in load_manifest():
            reachable = git("merge-base", "--is-ancestor", release.commit, "HEAD")
            assert reachable.returncode == 0, (
                f"{release.version} ({release.short_commit}) is not an ancestor of HEAD"
            )


class TestLedgerMatchesTheCode:
    def test_the_current_version_is_the_newest_entry_or_unreleased(self):
        """Either this checkout *is* the newest release, or it is ahead of it —
        never behind, which would mean a release was cut and never recorded."""
        newest = latest_release()
        assert version_key(__version__) >= version_key(newest.version), (
            f"version.py says {__version__} but {MANIFEST_NAME} already "
            f"records {newest.version}"
        )

    def test_the_current_version_agrees_where_it_is_recorded(self):
        release = find_release(__version__)
        if release is None:
            pytest.skip(f"{__version__} is not released yet")
        assert release.api_version == API_VERSION
        assert release.schema_version == SCHEMA_VERSION
        assert release.audit_payload_version == AUDIT_PAYLOAD_VERSION

    def test_every_release_has_a_changelog_section(self):
        changelog = (REPO / "CHANGELOG.md").read_text()
        for release in load_manifest():
            assert f"## [{release.version}] — {release.date}" in changelog, (
                f"CHANGELOG.md has no '## [{release.version}] — {release.date}' heading"
            )

    def test_every_release_has_its_compatibility_row(self):
        changelog = (REPO / "CHANGELOG.md").read_text()
        for release in load_manifest():
            row = (
                f"| {release.version} | {release.api_version} | "
                f"{release.schema_version} | {release.audit_payload_version} |"
            )
            assert row in changelog, f"missing compatibility row: {row}"

    def test_schema_versions_form_an_unbroken_run(self):
        """No gaps, or some deployment has no upgrade path to the next version.

        Compared as a *set*: most releases change no schema at all, and several
        consecutive releases sharing one schema version is the normal case, not
        a fault.
        """
        versions = sorted({release.schema_version for release in load_manifest()})
        assert versions == list(range(versions[0], versions[-1] + 1)), (
            f"schema versions skip a number: {versions}"
        )


class TestManifestFile:
    def test_the_file_on_disk_is_exactly_what_we_would_write(self):
        """Keeps a release diff to one added entry. A release commit that also
        reformats the file is a release commit nobody reads."""
        on_disk = (REPO / MANIFEST_NAME).read_text(encoding="utf-8")
        note = json.loads(on_disk)["$schema_note"]
        assert render_manifest(load_manifest(), note) == on_disk, (
            f"{MANIFEST_NAME} is not in canonical form; run "
            f"`make record-release` or reformat by hand"
        )

    def test_it_declares_the_manifest_version(self):
        document = json.loads((REPO / MANIFEST_NAME).read_text())
        assert document["manifest_version"] == MANIFEST_VERSION


class TestInvariants:
    """Each of these has a failure mode that is silent without the check."""

    def entry(self, **overrides) -> dict:
        base = {
            "version": "1.0.0",
            "commit": "a" * 40,
            "tag": "v1.0.0",
            "date": "2026-01-01",
            "api_version": "v1",
            "schema_version": 1,
            "audit_payload_version": 1,
        }
        return {**base, **overrides}

    def manifest(self, *entries: dict) -> str:
        return json.dumps({"manifest_version": 1, "releases": list(entries)})

    def test_a_valid_manifest_parses(self):
        parsed = parse_manifest(self.manifest(self.entry()))
        assert parsed == (Release(**self.entry()),)

    def test_an_abbreviated_sha_is_rejected(self):
        """Abbreviations become ambiguous as a repository grows, and the
        ledger has to still resolve in twenty years."""
        with pytest.raises(ManifestError, match="40-character"):
            parse_manifest(self.manifest(self.entry(commit="abc1234")))

    def test_a_mismatched_tag_is_rejected(self):
        with pytest.raises(ManifestError, match=r"expected 'v1\.0\.0'"):
            parse_manifest(self.manifest(self.entry(tag="release-1")))

    def test_a_repeated_version_is_rejected(self):
        with pytest.raises(ManifestError, match="recorded twice"):
            parse_manifest(self.manifest(self.entry(), self.entry(commit="b" * 40)))

    def test_two_versions_cannot_share_a_commit(self):
        with pytest.raises(ManifestError, match="same code"):
            parse_manifest(
                self.manifest(self.entry(), self.entry(version="1.0.1", tag="v1.0.1"))
            )

    def test_out_of_order_releases_are_rejected(self):
        with pytest.raises(ManifestError, match="append-only"):
            parse_manifest(
                self.manifest(
                    self.entry(version="1.1.0", tag="v1.1.0"),
                    self.entry(version="1.0.0", tag="v1.0.0", commit="b" * 40),
                )
            )

    def test_a_schema_version_may_not_go_backwards(self):
        """Databases migrate forward. A decrease means the ledger was edited."""
        with pytest.raises(ManifestError, match="schema version went backwards"):
            parse_manifest(
                self.manifest(
                    self.entry(schema_version=4),
                    self.entry(
                        version="1.0.1", tag="v1.0.1", commit="b" * 40, schema_version=3
                    ),
                )
            )

    def test_consecutive_releases_may_share_a_schema_version(self):
        """The common case: a release that changes no schema at all."""
        parsed = parse_manifest(
            self.manifest(
                self.entry(schema_version=4),
                self.entry(
                    version="1.0.1", tag="v1.0.1", commit="b" * 40, schema_version=4
                ),
            )
        )
        assert [release.schema_version for release in parsed] == [4, 4]

    def test_an_audit_payload_version_may_not_go_backwards(self):
        """A payload builder is never withdrawn, so its version never falls."""
        with pytest.raises(ManifestError, match="audit payload version went backwards"):
            parse_manifest(
                self.manifest(
                    self.entry(audit_payload_version=2),
                    self.entry(
                        version="1.0.1",
                        tag="v1.0.1",
                        commit="b" * 40,
                        audit_payload_version=1,
                    ),
                )
            )

    def test_an_unknown_manifest_version_fails_closed(self):
        """A newer ledger format read by an older build must refuse rather
        than silently ignore fields it does not know about."""
        with pytest.raises(ManifestError, match="manifest_version"):
            parse_manifest(json.dumps({"manifest_version": 99, "releases": []}))

    def test_unknown_keys_are_rejected(self):
        """A typo'd key would otherwise be accepted and silently mean nothing."""
        with pytest.raises(ManifestError, match="unknown keys"):
            parse_manifest(self.manifest(self.entry(sceham_version=1)))

    def test_a_missing_field_is_rejected(self):
        entry = self.entry()
        del entry["schema_version"]
        with pytest.raises(ManifestError, match="missing"):
            parse_manifest(self.manifest(entry))

    def test_malformed_json_is_rejected(self):
        with pytest.raises(ManifestError, match="not valid JSON"):
            parse_manifest("{not json")

    def test_an_empty_ledger_is_rejected(self):
        with pytest.raises(ManifestError, match="no releases"):
            parse_manifest(json.dumps({"manifest_version": 1, "releases": []}))

    def test_a_malformed_version_is_rejected(self):
        with pytest.raises(ManifestError, match=r"MAJOR\.MINOR\.PATCH"):
            version_key("1.0")


class TestReleaseLabel:
    def test_the_label_matches_what_that_build_would_report(self):
        """``version_label()`` on the released commit produces exactly this,
        so a ledger entry can be matched back to a release without guessing."""
        release = Release(
            version="0.4.0",
            commit="8670e937a7af5bc9cb4936a205844477f6b81b4c",
            tag="v0.4.0",
            date="2026-08-09",
            api_version="v1",
            schema_version=4,
            audit_payload_version=2,
        )
        assert release.label == "0.4.0+g8670e93"
