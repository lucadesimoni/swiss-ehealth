# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Append component releases to ``COMPONENTS.json``.

Run by ``make record-component-release`` after ``make release-component`` has
cut the tag. The entry lands one commit later than the code it describes — the
same honest ordering ``record_release.py`` uses, for the same reason: you
cannot know a commit's hash before you have made it.

**Where the recorded commit comes from.** The component's annotated tag, when
it exists: the tag *is* the statement of which commit that version was cut
from, so reading it back means the ledger and the tag cannot disagree — and
``test_tags_agree_with_the_ledger_where_they_exist`` is precisely the check
that would otherwise fail. Only when no tag exists yet does this fall back to
``HEAD``, and only then does a dirty tree matter, because only then is the
commit inferred from what is on disk rather than read from a tag.

That distinction is what makes recording order-independent. Two ledgers cannot
both be recorded from a clean tree in one commit — whichever runs second sees
the first one's edit — and a component ledger keyed to ``HEAD`` would then
record the wrong commit.

With no argument it records every component whose declared version is not yet
in the ledger, which is what cutting the baseline needs. With
``--component NAME`` it records exactly one.

Everything written here is read back out of the repository rather than typed
in, so an entry cannot disagree with the code it points at.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

from ehealth.components import (
    MANIFEST_NAME,
    ComponentError,
    ComponentRelease,
    find_component,
    find_component_release,
    load_manifest,
    parse_manifest,
    render_manifest,
    unreleased_components,
)
from ehealth.releases import repo_root

NOTE = (
    "The component ledger. See docs/versioning.md. Append-only: an entry, "
    "once committed, is never edited or removed. Each entry is checked "
    "against the repository by tests/test_components.py, which parses "
    "src/ehealth/components.py at the recorded commit and requires "
    "COMPONENT_VERSIONS to declare exactly this version for this component. "
    "An empty list is legitimate: the registry may declare a component before "
    "it has ever been cut."
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


def git_or_none(*args: str) -> str | None:
    """For questions where "no" is an answer, not a failure."""
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root(),
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def commit_of_tag(tag: str) -> str | None:
    return git_or_none("rev-list", "-n1", tag)


def software_version_at(commit: str) -> str | None:
    """The ``__version__`` that commit declares.

    Read out of the commit rather than off the disk, so an entry recorded later
    still names the version that was actually in force when the component was
    cut. Textual, because importing the module would run it.
    """
    shown = git_or_none("show", f"{commit}:src/ehealth/version.py")
    if shown is None:
        return None
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', shown, re.MULTILINE)
    return match.group(1) if match else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--component",
        help="record only this component; default is every unrecorded one",
    )
    arguments = parser.parse_args(argv)

    try:
        existing = load_manifest()
    except ComponentError as exc:
        print(
            f"{MANIFEST_NAME} is unusable, refusing to append: {exc}", file=sys.stderr
        )
        return 1

    if arguments.component:
        component = find_component(arguments.component)
        if component is None:
            print(
                f"{arguments.component!r} is not a component of this system",
                file=sys.stderr,
            )
            return 1
        if find_component_release(component.name, component.version) is not None:
            print(
                f"{component.name} {component.version} is already in "
                f"{MANIFEST_NAME}. The ledger is append-only; a mistake gets a "
                f"new version, never a corrected entry.",
                file=sys.stderr,
            )
            return 1
        pending = (component,)
    else:
        pending = unreleased_components()

    if not pending:
        print("every declared component version is already recorded")
        return 0

    # A component with no tag yet is recorded from HEAD, which is only
    # meaningful if HEAD describes what is on disk.
    if any(commit_of_tag(component.tag) is None for component in pending):
        if git("status", "--porcelain"):
            print(
                "refusing to infer a component's commit from HEAD on a dirty "
                "tree: the recorded commit would not describe what is on disk. "
                "Cut the tag first with `make release-component`, or commit.",
                file=sys.stderr,
            )
            return 1

    entries: list[ComponentRelease] = []
    for component in pending:
        commit = commit_of_tag(component.tag) or git("rev-parse", "HEAD")
        declared = software_version_at(commit)
        if declared is None:
            print(
                f"cannot read the software version at {commit[:7]}, so "
                f"{component.name} {component.version} cannot be recorded",
                file=sys.stderr,
            )
            return 1
        entries.append(
            ComponentRelease(
                component=component.name,
                tier=component.tier,
                version=component.version,
                commit=commit,
                tag=component.tag,
                date=git(
                    "show", "-s", "--format=%cd", "--date=format:%Y-%m-%d", commit
                ),
                software_version=declared,
            )
        )

    rendered = render_manifest((*existing, *entries), NOTE)
    # Parse what we are about to write, so a violated invariant is caught
    # before it reaches the file rather than by the next person's test run.
    try:
        parse_manifest(rendered)
    except ComponentError as exc:
        print(f"the resulting ledger would be invalid: {exc}", file=sys.stderr)
        return 1

    (repo_root() / MANIFEST_NAME).write_text(rendered, encoding="utf-8")
    for entry in entries:
        print(f"recorded {entry.component} {entry.version} at {entry.short_commit}")
    print(f"now commit {MANIFEST_NAME} and push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
