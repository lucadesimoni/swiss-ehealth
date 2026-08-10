# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Append component releases to ``COMPONENTS.json``.

Run by ``make record-component-release`` immediately after the commit that
carries the component version exists, so the recorded SHA is that commit and
not the commit which records it. The entry therefore lands one commit later
than the code it describes — the same honest ordering ``record_release.py``
uses, for the same reason: you cannot know a commit's hash before you have
made it.

With no argument it records every component whose declared version is not yet
in the ledger, which is what cutting the baseline needs. With
``--component NAME`` it records exactly one.

Everything written here is read back out of the repository rather than typed
in, so an entry cannot disagree with the code it points at.
"""

from __future__ import annotations

import argparse
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
from ehealth.version import __version__

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--component",
        help="record only this component; default is every unrecorded one",
    )
    arguments = parser.parse_args(argv)

    if git("status", "--porcelain"):
        print(
            "refusing to record a component release from a dirty tree: the "
            "recorded commit would not describe what is on disk",
            file=sys.stderr,
        )
        return 1

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

    commit = git("rev-parse", "HEAD")
    date = git("show", "-s", "--format=%cd", "--date=format:%Y-%m-%d", "HEAD")

    entries = [
        ComponentRelease(
            component=component.name,
            tier=component.tier,
            version=component.version,
            commit=commit,
            tag=component.tag,
            date=date,
            software_version=__version__,
        )
        for component in pending
    ]

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
