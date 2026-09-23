# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Recreate every release and component tag from the two ledgers.

For a clone that has ``RELEASES.json`` and ``COMPONENTS.json`` but not the
tags — which is every clone for as long as tags cannot be pushed from where
releases are cut. The ledgers are the durable record; this turns them back
into the ergonomic handle.

Each tag is annotated, points at the commit its ledger entry records, and
carries that commit's date as its tagger date, so it does not claim to have
been made on the day it was rebuilt. An existing tag is kept if it already
points at the right commit and reported if it points anywhere else — tags are
never moved, so a disagreement is for a person to resolve, not this script.

Run ``git push origin --tags`` afterwards to publish them.
"""

from __future__ import annotations

import os
import subprocess
import sys

from ehealth.components import load_manifest as load_component_manifest
from ehealth.releases import load_manifest, repo_root


def git(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def main() -> int:
    wanted = [(r.tag, r.commit) for r in load_manifest()]
    wanted += [(c.tag, c.commit) for c in load_component_manifest()]

    created = kept = 0
    conflicts: list[str] = []
    for tag, commit in wanted:
        existing = git("rev-list", "-n1", tag)
        if existing.returncode == 0:
            if existing.stdout.strip() == commit:
                kept += 1
            else:
                conflicts.append(
                    f"{tag} points at {existing.stdout.strip()[:7]}, "
                    f"the ledger says {commit[:7]}"
                )
            continue

        present = git("cat-file", "-e", f"{commit}^{{commit}}")
        if present.returncode != 0:
            conflicts.append(f"{tag}: commit {commit[:7]} is not in this clone")
            continue

        date = git("show", "-s", "--format=%cI", commit).stdout.strip()
        made = git(
            "tag",
            "-a",
            tag,
            commit,
            "-m",
            f"swiss-ehealth {tag}",
            env={**os.environ, "GIT_COMMITTER_DATE": date},
        )
        if made.returncode != 0:
            conflicts.append(f"{tag}: {made.stderr.strip()}")
            continue
        created += 1
        print(f"created {tag} at {commit[:7]} ({date[:10]})")

    print(f"{created} created, {kept} already correct, {len(conflicts)} refused")
    for conflict in conflicts:
        print(f"refused: {conflict}", file=sys.stderr)
    if created:
        print("publish with: git push origin --tags")
    return 1 if conflicts else 0


if __name__ == "__main__":
    raise SystemExit(main())
