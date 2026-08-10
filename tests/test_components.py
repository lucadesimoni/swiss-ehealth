# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The component registry and its ledger, checked against the repository.

Two tests here earn their keep.

:meth:`TestRegistry.test_every_file_is_owned_by_exactly_one_component` is what
keeps the scheme honest as the code grows. A component version is a promise
about a set of files; a file owned by nothing is covered by no promise, and
nobody notices, because nothing breaks until an integrator trusts a version
that did not account for it.

:meth:`TestLedgerMatchesTheRepository.test_every_entry_matches_its_commit`
is the check a fabricated entry cannot survive: it parses
``src/ehealth/components.py`` *at each recorded commit* and requires
``COMPONENT_VERSIONS`` to declare exactly the version the entry claims. It
parses rather than imports, because verifying what a component declared two
years ago must not mean executing two-year-old code.
"""

from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

from ehealth.components import (
    COMPONENT_VERSIONS,
    COMPONENTS,
    MANIFEST_NAME,
    MANIFEST_VERSION,
    TIERS,
    Component,
    ComponentError,
    ComponentRelease,
    component_versions,
    components_by_tier,
    declared_versions_in,
    find_component,
    latest_release_of,
    load_manifest,
    owner_of,
    parse_manifest,
    render_manifest,
)
from ehealth.releases import ManifestError, version_key
from ehealth.version import __version__

REPO = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = REPO / "src" / "ehealth"


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=False
    )


@pytest.fixture(scope="session")
def repository_history_available() -> bool:
    """Skip the history checks where the history is not there to check.

    A shallow clone — the CI default — genuinely cannot resolve older commits.
    Skipping is honest; passing would not be.
    """
    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    if git("rev-parse", "--is-shallow-repository").stdout.strip() == "true":
        pytest.skip("shallow clone: recorded commits are not present to verify")
    return True


class TestRegistry:
    def test_every_file_is_owned_by_exactly_one_component(self):
        """The check that keeps the scheme meaningful as the code grows."""
        unowned: list[str] = []
        shared: list[tuple[str, list[str]]] = []

        for path in sorted(PACKAGE.rglob("*.py")):
            relative = path.relative_to(PACKAGE).as_posix()
            owners = [c.name for c in COMPONENTS if c.owns(relative)]
            if not owners:
                unowned.append(relative)
            elif len(owners) > 1:
                shared.append((relative, owners))

        assert not unowned, (
            f"these files belong to no component, so no component's version "
            f"describes their changes: {unowned}. Add each to a component in "
            f"src/ehealth/components.py."
        )
        assert not shared, (
            f"these files are claimed by more than one component, so a bump of "
            f"either would be a half-truth: {shared}"
        )

    def test_every_declared_path_exists(self):
        """A stale path silently owns nothing, which looks like coverage."""
        for component in COMPONENTS:
            for declared in component.paths:
                target = PACKAGE / declared.rstrip("/")
                assert target.exists(), (
                    f"{component.name} claims {declared!r}, which does not exist"
                )
                if declared.endswith("/"):
                    assert target.is_dir(), f"{declared!r} is not a directory"
                else:
                    assert target.is_file(), f"{declared!r} is not a file"

    def test_owner_of_agrees_with_the_registry(self):
        assert owner_of("services/persons.py").name == "persons"
        assert owner_of("domain/uid.py").name == "core"
        assert owner_of("config.py").name == "platform"
        assert owner_of("nothing/here.py") is None

    def test_models_are_core_but_services_are_modules(self):
        """The split that makes the tiers worth having: every module stores
        through the shared ORM models, so those are kernel, while the logic
        that uses them is not."""
        assert owner_of("models/audit.py").name == "core"
        assert owner_of("services/audit.py").name == "audit"

    def test_every_version_is_semver(self):
        for name, version in COMPONENT_VERSIONS.items():
            assert version_key(version), f"{name}: {version}"

    def test_tiers_are_known_and_singular_where_they_must_be(self):
        for component in COMPONENTS:
            assert component.tier in TIERS
        for tier in ("platform", "core"):
            assert [c.name for c in COMPONENTS if c.tier == tier] == [tier]
        assert any(c.tier == "module" for c in COMPONENTS)

    def test_tags_are_unique_and_namespaced(self):
        tags = [component.tag for component in COMPONENTS]
        assert len(tags) == len(set(tags))
        for component in COMPONENTS:
            if component.tier == "module":
                assert component.tag.startswith(f"module/{component.name}/v")
            else:
                assert component.tag.startswith(f"{component.name}/v")

    def test_no_component_tag_can_look_like_a_release_tag(self):
        """``v0.5.0`` is the software release. A component tag must never be
        mistakable for one, or `git describe` becomes a coin toss."""
        for component in COMPONENTS:
            assert not component.tag.startswith("v")

    def test_tiers_are_ordered_by_blast_radius(self):
        """`components_by_tier` puts the widest-reaching first, which is the
        order a reader assessing an upgrade needs."""
        tiers = [component.tier for component in components_by_tier()]
        assert tiers == sorted(tiers, key=lambda tier: -TIERS.index(tier))
        assert tiers[0] == "platform"
        assert tiers[-1] == "module"

    def test_every_component_has_a_summary(self):
        for component in COMPONENTS:
            assert component.summary.strip()

    def test_component_versions_reports_every_component(self):
        assert set(component_versions()) == {c.name for c in COMPONENTS}


class TestLedgerMatchesTheRepository:
    def test_every_entry_matches_its_commit(self, repository_history_available):
        """The check a fabricated entry cannot survive."""
        for entry in load_manifest():
            resolved = git("rev-parse", "--verify", f"{entry.commit}^{{commit}}")
            assert resolved.returncode == 0, (
                f"{MANIFEST_NAME} records commit {entry.commit} for "
                f"{entry.component} {entry.version}, which is not in this "
                f"repository"
            )

            shown = git("show", f"{entry.commit}:src/ehealth/components.py")
            assert shown.returncode == 0, (
                f"commit {entry.short_commit} has no src/ehealth/components.py, "
                f"so it cannot have declared {entry.component} {entry.version}"
            )
            declared = declared_versions_in(shown.stdout)
            assert declared.get(entry.component) == entry.version, (
                f"{MANIFEST_NAME} claims {entry.component} {entry.version} at "
                f"{entry.short_commit}, but that commit declares "
                f"{declared.get(entry.component)!r}"
            )

    def test_the_recorded_software_version_is_the_one_in_force(
        self, repository_history_available
    ):
        for entry in load_manifest():
            shown = git("show", f"{entry.commit}:src/ehealth/version.py")
            assert shown.returncode == 0
            assert f'__version__ = "{entry.software_version}"' in shown.stdout, (
                f"{entry.component} {entry.version} records software version "
                f"{entry.software_version}, which is not what "
                f"{entry.short_commit} declares"
            )

    def test_recorded_dates_are_the_commit_dates(self, repository_history_available):
        for entry in load_manifest():
            committed = git(
                "show", "-s", "--format=%cd", "--date=format:%Y-%m-%d", entry.commit
            ).stdout.strip()
            assert entry.date == committed, (
                f"{entry.component} {entry.version} is dated {entry.date} but "
                f"its commit was made on {committed}"
            )

    def test_tags_agree_with_the_ledger_where_they_exist(
        self, repository_history_available
    ):
        """Tags are the convenient handle, the ledger is the durable one, and a
        disagreement between them means one of the two is lying."""
        for entry in load_manifest():
            resolved = git("rev-list", "-n1", entry.tag)
            if resolved.returncode != 0:
                continue  # tag absent here — the ledger still stands alone
            assert resolved.stdout.strip() == entry.commit, (
                f"tag {entry.tag} points at {resolved.stdout.strip()[:7]} but "
                f"{MANIFEST_NAME} records {entry.short_commit}. A published tag "
                f"is never moved; fix the tag, not the ledger."
            )

    def test_component_tags_are_annotated(self, repository_history_available):
        """A lightweight tag carries no author, date or message and is not an
        object in the repository. The policy is annotated, always."""
        for entry in load_manifest():
            if git("rev-parse", "--verify", entry.tag).returncode != 0:
                continue
            kind = git("cat-file", "-t", entry.tag).stdout.strip()
            assert kind == "tag", (
                f"{entry.tag} is a {kind}, not an annotated tag object"
            )

    def test_recorded_commits_are_ancestors_of_this_commit(
        self, repository_history_available
    ):
        for entry in load_manifest():
            reachable = git("merge-base", "--is-ancestor", entry.commit, "HEAD")
            assert reachable.returncode == 0, (
                f"{entry.component} {entry.version} ({entry.short_commit}) is "
                f"not an ancestor of HEAD"
            )


class TestLedgerMatchesTheCode:
    def test_no_component_is_behind_its_ledger(self):
        """Either the declared version *is* the newest recorded one, or it is
        ahead of it — never behind, which would mean a component release was
        cut and then the version walked backwards."""
        for component in COMPONENTS:
            newest = latest_release_of(component.name)
            if newest is None:
                continue
            assert version_key(component.version) >= version_key(newest.version), (
                f"{component.name} declares {component.version} but "
                f"{MANIFEST_NAME} already records {newest.version}"
            )

    def test_the_recorded_tier_still_matches_the_registry(self):
        for entry in load_manifest():
            assert entry.tier == find_component(entry.component).tier


class TestManifestFile:
    def test_the_file_on_disk_is_exactly_what_we_would_write(self):
        """Keeps a release diff to the added entries and nothing else."""
        on_disk = (REPO / MANIFEST_NAME).read_text(encoding="utf-8")
        note = json.loads(on_disk)["$schema_note"]
        assert render_manifest(load_manifest(), note) == on_disk, (
            f"{MANIFEST_NAME} is not in canonical form; run "
            f"`make record-component-release` or reformat by hand"
        )

    def test_it_declares_the_manifest_version(self):
        document = json.loads((REPO / MANIFEST_NAME).read_text())
        assert document["manifest_version"] == MANIFEST_VERSION


class TestReadingAPastDeclaration:
    """``declared_versions_in`` is how the ledger is checked against history,
    so its failure modes matter as much as its successes."""

    def test_it_reads_the_dict(self):
        source = 'COMPONENT_VERSIONS: dict[str, str] = {"core": "1.2.3"}\n'
        assert declared_versions_in(source) == {"core": "1.2.3"}

    def test_it_reads_an_unannotated_assignment(self):
        assert declared_versions_in('COMPONENT_VERSIONS = {"core": "1.0.0"}') == {
            "core": "1.0.0"
        }

    def test_it_does_not_execute_the_module(self):
        """Verifying a two-year-old declaration must not run two-year-old code."""
        source = (
            "raise SystemExit('this must never run')\n"
            'COMPONENT_VERSIONS = {"core": "9.9.9"}\n'
        )
        assert declared_versions_in(source) == {"core": "9.9.9"}

    def test_a_file_without_the_declaration_is_refused(self):
        with pytest.raises(ComponentError, match="no COMPONENT_VERSIONS"):
            declared_versions_in("x = 1\n")

    def test_unparseable_source_is_refused(self):
        with pytest.raises(ComponentError, match="cannot parse"):
            declared_versions_in("def (\n")

    def test_a_non_literal_declaration_is_refused(self):
        """A computed dict cannot be read without running it, and running it is
        exactly what this must not do."""
        with pytest.raises(ComponentError):
            declared_versions_in("COMPONENT_VERSIONS = dict(core=some_call())")


class TestInvariants:
    """Each of these has a failure mode that is silent without the check."""

    def entry(self, **overrides) -> dict:
        base = {
            "component": "persons",
            "tier": "module",
            "version": "1.0.0",
            "commit": "a" * 40,
            "tag": "module/persons/v1.0.0",
            "date": "2026-01-01",
            "software_version": "1.0.0",
        }
        return {**base, **overrides}

    def manifest(self, *entries: dict) -> str:
        return json.dumps({"manifest_version": 1, "component_releases": list(entries)})

    def test_a_valid_manifest_parses(self):
        parsed = parse_manifest(self.manifest(self.entry()))
        assert parsed == (ComponentRelease(**self.entry()),)

    def test_an_empty_ledger_is_accepted(self):
        """Unlike the release ledger: the registry legitimately declares
        components before any of them has been cut."""
        assert parse_manifest(self.manifest()) == ()

    def test_an_abbreviated_sha_is_rejected(self):
        with pytest.raises(ComponentError, match="40-character"):
            parse_manifest(self.manifest(self.entry(commit="abc1234")))

    def test_an_unknown_component_is_rejected(self):
        with pytest.raises(ComponentError, match="not a component"):
            parse_manifest(
                self.manifest(
                    self.entry(component="telepathy", tag="module/telepathy/v1.0.0")
                )
            )

    def test_a_tier_that_contradicts_the_registry_is_rejected(self):
        with pytest.raises(ComponentError, match="registry says"):
            parse_manifest(self.manifest(self.entry(tier="core")))

    def test_a_mismatched_tag_is_rejected(self):
        with pytest.raises(ComponentError, match="expected"):
            parse_manifest(self.manifest(self.entry(tag="v1.0.0")))

    def test_a_module_tag_must_be_namespaced(self):
        with pytest.raises(ComponentError, match="expected"):
            parse_manifest(self.manifest(self.entry(tag="persons/v1.0.0")))

    def test_a_repeated_version_is_rejected(self):
        with pytest.raises(ComponentError, match="append-only"):
            parse_manifest(self.manifest(self.entry(), self.entry(commit="b" * 40)))

    def test_out_of_order_versions_are_rejected(self):
        with pytest.raises(ComponentError, match="append-only"):
            parse_manifest(
                self.manifest(
                    self.entry(version="1.1.0", tag="module/persons/v1.1.0"),
                    self.entry(
                        version="1.0.0",
                        tag="module/persons/v1.0.0",
                        commit="b" * 40,
                    ),
                )
            )

    def test_one_component_cannot_release_twice_from_one_commit(self):
        with pytest.raises(ComponentError, match="same code"):
            parse_manifest(
                self.manifest(
                    self.entry(),
                    self.entry(version="1.0.1", tag="module/persons/v1.0.1"),
                )
            )

    def test_different_components_may_share_a_commit(self):
        """The baseline case: every component cut from the same commit. A
        global 'one version per commit' rule would forbid it wrongly."""
        parsed = parse_manifest(
            self.manifest(
                self.entry(),
                self.entry(component="dossier", tag="module/dossier/v1.0.0"),
            )
        )
        assert [entry.component for entry in parsed] == ["persons", "dossier"]

    def test_versions_of_different_components_are_independent(self):
        """persons at 2.0.0 says nothing about dossier, which is the point."""
        parsed = parse_manifest(
            self.manifest(
                self.entry(version="2.0.0", tag="module/persons/v2.0.0"),
                self.entry(
                    component="dossier",
                    tag="module/dossier/v1.0.0",
                    commit="b" * 40,
                ),
            )
        )
        assert [entry.version for entry in parsed] == ["2.0.0", "1.0.0"]

    def test_an_unknown_manifest_version_fails_closed(self):
        with pytest.raises(ComponentError, match="manifest_version"):
            parse_manifest(
                json.dumps({"manifest_version": 99, "component_releases": []})
            )

    def test_a_missing_releases_list_is_rejected(self):
        with pytest.raises(ComponentError, match="component_releases"):
            parse_manifest(json.dumps({"manifest_version": 1}))

    def test_unknown_keys_are_rejected(self):
        with pytest.raises(ComponentError, match="unknown keys"):
            parse_manifest(self.manifest(self.entry(teir="module")))

    def test_a_missing_field_is_rejected(self):
        entry = self.entry()
        del entry["software_version"]
        with pytest.raises(ComponentError, match="missing"):
            parse_manifest(self.manifest(entry))

    def test_malformed_json_is_rejected(self):
        with pytest.raises(ComponentError, match="not valid JSON"):
            parse_manifest("{not json")

    def test_a_component_error_is_catchable_as_a_manifest_error(self):
        """One except clause can cover either ledger being unusable."""
        with pytest.raises(ManifestError):
            parse_manifest("{not json")


class TestRegistryRefusesContradictions:
    """The registry validates itself at import. These reproduce each refusal
    against a constructed component rather than by breaking the real one."""

    def component(self, **overrides) -> Component:
        base = {
            "name": "persons",
            "tier": "module",
            "summary": "s",
            "paths": ("services/persons.py",),
        }
        return Component(**{**base, **overrides})

    def test_a_directory_path_owns_its_tree(self):
        component = self.component(paths=("services/",))
        assert component.owns("services/persons.py")
        assert component.owns("services/deeply/nested.py")
        assert not component.owns("api/routes_persons.py")

    def test_a_file_path_owns_only_that_file(self):
        component = self.component(paths=("services/persons.py",))
        assert component.owns("services/persons.py")
        assert not component.owns("services/persons_extra.py")

    def test_a_module_tag_is_namespaced_under_module(self):
        assert self.component().ref_prefix == "module/persons"

    def test_a_core_tag_is_not(self):
        assert self.component(name="core", tier="core").ref_prefix == "core"


class TestVersionEndpointReportsComponents:
    def test_it_reports_every_component_version(self, client):
        body = client.get("/v1/version").json()
        assert body["components"] == component_versions()

    def test_the_software_version_is_still_reported_alongside(self, client):
        body = client.get("/v1/version").json()
        assert body["version"] == __version__

    def test_components_stay_behind_the_admin_key(self, client):
        """Knowing which module versions are deployed narrows an attacker's
        search as much as the build revision does."""
        response = client.get("/v1/version", headers={"X-Admin-Key": "wrong"})
        assert response.status_code == 401
