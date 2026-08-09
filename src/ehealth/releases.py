# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The release ledger: which version was cut, and from which commit.

An annotated tag is the conventional answer to "what is 0.3.0?", and this
project cuts one for every release. But a tag is a mutable pointer that lives
*beside* the history rather than in it: it can be moved, deleted, or — as
happens on locked-down mirrors and in restricted CI networks — simply never
reach the remote at all. A clone with no tags then has no way to say which
commit was released, and the commit subjects are prose, not a record.

``RELEASES.json`` closes that. It is a plain file inside the tree, so it is
carried by every clone, covered by git's own hashing, and versioned by the
history like everything else. Tags remain the ergonomic handle; the ledger is
the durable one, and :mod:`tests.test_releases` requires the two to agree
wherever both exist.

The invariants below are the ones that make an entry worth trusting. The
strongest check is not here but in the test suite, because it needs the
repository: for every entry it reads ``src/ehealth/version.py`` *at the
recorded commit* and requires it to declare exactly the numbers claimed. A
mistyped or invented SHA cannot survive that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

#: Layout of ``RELEASES.json`` itself, so a future reshuffle of the file is
#: distinguishable from a corrupt one.
MANIFEST_VERSION = 1

MANIFEST_NAME = "RELEASES.json"


class ManifestError(Exception):
    """The release ledger is unusable — malformed, or self-contradictory."""


@dataclass(frozen=True, slots=True)
class Release:
    """One released version, bound to the commit it was cut from."""

    version: str
    commit: str
    tag: str
    date: str
    api_version: str
    schema_version: int
    audit_payload_version: int

    @property
    def short_commit(self) -> str:
        return self.commit[:7]

    @property
    def label(self) -> str:
        """The same form ``version_label()`` produces for this commit, so a
        ledger entry written by that release can be matched against it."""
        return f"{self.version}+g{self.short_commit}"


def version_key(version: str) -> tuple[int, int, int]:
    """Sort key for a plain ``MAJOR.MINOR.PATCH``.

    Deliberately narrow: this project's released versions have no pre-release
    or build suffixes, and a lenient parser here would let a malformed version
    sort somewhere arbitrary instead of failing.
    """
    parts = version.split(".")
    if len(parts) != 3:
        raise ManifestError(f"not a MAJOR.MINOR.PATCH version: {version!r}")
    try:
        major, minor, patch = (int(part) for part in parts)
    except ValueError as exc:
        raise ManifestError(f"not a MAJOR.MINOR.PATCH version: {version!r}") from exc
    return major, minor, patch


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def parse_manifest(raw: str) -> tuple[Release, ...]:
    """Parse and validate the ledger, in file order.

    Order is meaningful and is checked rather than repaired: sorting a
    contradictory file would hide the contradiction.
    """
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"{MANIFEST_NAME} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise ManifestError(f"{MANIFEST_NAME} must contain an object")

    declared = document.get("manifest_version")
    if declared != MANIFEST_VERSION:
        raise ManifestError(
            f"{MANIFEST_NAME} declares manifest_version {declared!r}, "
            f"this build understands {MANIFEST_VERSION}"
        )

    entries = document.get("releases")
    if not isinstance(entries, list) or not entries:
        raise ManifestError(f"{MANIFEST_NAME} has no releases")

    releases: list[Release] = []
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ManifestError(f"release at position {position} is not an object")
        missing = {field.name for field in Release.__dataclass_fields__.values()} - set(
            entry
        )
        if missing:
            raise ManifestError(
                f"release at position {position} is missing {sorted(missing)}"
            )
        unexpected = set(entry) - set(Release.__dataclass_fields__)
        if unexpected:
            raise ManifestError(
                f"release at position {position} has unknown keys {sorted(unexpected)}"
            )
        releases.append(Release(**entry))

    _check_invariants(tuple(releases))
    return tuple(releases)


def _check_invariants(releases: tuple[Release, ...]) -> None:
    """The self-consistency a reader is entitled to assume."""
    seen_versions: set[str] = set()
    seen_commits: set[str] = set()
    previous: Release | None = None

    for release in releases:
        if len(release.commit) != 40 or not all(
            character in "0123456789abcdef" for character in release.commit
        ):
            raise ManifestError(
                f"{release.version}: commit must be a full 40-character SHA, "
                f"got {release.commit!r}. An abbreviated SHA can become "
                f"ambiguous as the repository grows."
            )
        if release.tag != f"v{release.version}":
            raise ManifestError(
                f"{release.version}: tag is {release.tag!r}, expected "
                f"'v{release.version}'"
            )
        if release.version in seen_versions:
            raise ManifestError(f"{release.version} is recorded twice")
        if release.commit in seen_commits:
            raise ManifestError(
                f"{release.version}: commit {release.short_commit} is already "
                f"recorded for another version — two versions cannot be the "
                f"same code"
            )
        seen_versions.add(release.version)
        seen_commits.add(release.commit)

        if previous is not None:
            if version_key(release.version) <= version_key(previous.version):
                raise ManifestError(
                    f"{release.version} does not come after {previous.version}; "
                    f"the ledger is in release order and is append-only"
                )
            # Compatibility numbers describe accumulated state: the database
            # is migrated forward, and an audit payload builder is never
            # withdrawn. A decrease means someone edited history.
            if release.schema_version < previous.schema_version:
                raise ManifestError(
                    f"{release.version}: schema version went backwards "
                    f"({previous.schema_version} → {release.schema_version})"
                )
            if release.audit_payload_version < previous.audit_payload_version:
                raise ManifestError(
                    f"{release.version}: audit payload version went backwards "
                    f"({previous.audit_payload_version} → "
                    f"{release.audit_payload_version})"
                )
        previous = release


@lru_cache
def load_manifest() -> tuple[Release, ...]:
    """The ledger for this checkout.

    Raises rather than returning empty when the file is absent: a build that
    cannot state its release history should say so, not imply there is none.
    """
    path = repo_root() / MANIFEST_NAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    return parse_manifest(raw)


def latest_release() -> Release:
    return load_manifest()[-1]


def find_release(version: str) -> Release | None:
    for release in load_manifest():
        if release.version == version:
            return release
    return None


def render_manifest(releases: tuple[Release, ...], note: str) -> str:
    """Serialise the ledger back to the exact on-disk form.

    Byte-stable so that appending a release produces a one-entry diff and
    nothing else — a release commit that reformats the file is a release commit
    nobody reads.
    """
    document = {
        "$schema_note": note,
        "manifest_version": MANIFEST_VERSION,
        "releases": [
            {
                "version": release.version,
                "commit": release.commit,
                "tag": release.tag,
                "date": release.date,
                "api_version": release.api_version,
                "schema_version": release.schema_version,
                "audit_payload_version": release.audit_payload_version,
            }
            for release in releases
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
