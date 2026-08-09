# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Append the current commit to ``RELEASES.json``.

Run by ``make record-release`` immediately after the release commit exists, so
the recorded SHA is the commit that actually carries the release — not the
commit that records it. The ledger entry therefore lands one commit later than
the release it describes, which is the honest ordering: you cannot know a
commit's hash before you have made it.

Everything written here is read back out of the repository rather than typed
in, so the entry cannot disagree with the code it points at.
"""

from __future__ import annotations

import subprocess
import sys

from ehealth.releases import (
    MANIFEST_NAME,
    ManifestError,
    Release,
    load_manifest,
    parse_manifest,
    render_manifest,
    repo_root,
)
from ehealth.version import (
    API_VERSION,
    AUDIT_PAYLOAD_VERSION,
    SCHEMA_VERSION,
    __version__,
)

NOTE = (
    "The release ledger. See docs/versioning.md. Append-only: an entry, once "
    "committed, is never edited or removed. Each entry is checked against the "
    "repository by tests/test_releases.py, which reads src/ehealth/version.py "
    "at the recorded commit and requires it to declare exactly these numbers."
)


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def main() -> int:
    if git("status", "--porcelain"):
        print(
            "refusing to record a release from a dirty tree: the recorded "
            "commit would not describe what is on disk",
            file=sys.stderr,
        )
        return 1

    try:
        existing = load_manifest()
    except ManifestError as exc:
        print(
            f"{MANIFEST_NAME} is unusable, refusing to append: {exc}", file=sys.stderr
        )
        return 1

    if any(release.version == __version__ for release in existing):
        print(
            f"{__version__} is already in {MANIFEST_NAME}. The ledger is "
            f"append-only; a mistake gets a new version, never a corrected "
            f"entry.",
            file=sys.stderr,
        )
        return 1

    entry = Release(
        version=__version__,
        commit=git("rev-parse", "HEAD"),
        tag=f"v{__version__}",
        date=git("show", "-s", "--format=%cd", "--date=format:%Y-%m-%d", "HEAD"),
        api_version=API_VERSION,
        schema_version=SCHEMA_VERSION,
        audit_payload_version=AUDIT_PAYLOAD_VERSION,
    )

    rendered = render_manifest((*existing, entry), NOTE)
    # Parse what we are about to write, so a violated invariant is caught
    # before it reaches the file rather than by the next person's test run.
    try:
        parse_manifest(rendered)
    except ManifestError as exc:
        print(f"the resulting ledger would be invalid: {exc}", file=sys.stderr)
        return 1

    (repo_root() / MANIFEST_NAME).write_text(rendered, encoding="utf-8")
    print(f"recorded {entry.version} at {entry.short_commit} ({entry.date})")
    print(f"now commit {MANIFEST_NAME} and push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
