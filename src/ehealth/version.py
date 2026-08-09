# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Release identity of the running code.

Five things version independently in this system, because they change for
different reasons and break different consumers:

===================== ============================================= ===========
What                  Breaks when it changes                        Lives in
===================== ============================================= ===========
``__version__``       nothing on its own — it *describes*           here
``API_VERSION``       every HTTP client                             URL / docs
``SCHEMA_VERSION``    the database, so a migration is required      here
``AUDIT_PAYLOAD_VERSION`` the signed audit payload layout, so old   here
                      entries need their old builder to verify
key versions          nothing — old material stays verifiable       ``KeyRing``
===================== ============================================= ===========

Conflating them is the usual mistake: a patch release that quietly changes the
audit payload layout makes every earlier ledger entry unverifiable, and nobody
notices until an audit. Keeping them separate means each has its own
compatibility promise, and :func:`release_identity` reports all of them at once
so a deployed instance can be traced back to a commit and a format.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path

#: Semantic version of the software release. The single source of truth —
#: ``pyproject.toml`` and ``CHANGELOG.md`` are checked against it by
#: ``tests/test_versioning.py``, so the three can never drift apart.
__version__ = "0.4.0"

#: HTTP API contract. Bumped only on a breaking change to routes or payloads.
API_VERSION = "v1"

#: Database schema. Every migration bumps this.
SCHEMA_VERSION = 4

#: Layout of the signed audit payload. Bumping it means older entries must
#: still be verifiable with the builder they were written under, which is why
#: :mod:`ehealth.services.audit` keeps a builder per version rather than one
#: function that evolves.
AUDIT_PAYLOAD_VERSION = 2

#: Set by the build pipeline. Falls back to asking git in a working checkout,
#: and to "unknown" in neither case — a wrong revision is worse than none.
REVISION_ENV_VAR = "EHEALTH_GIT_REVISION"
BUILD_TIMESTAMP_ENV_VAR = "EHEALTH_BUILD_TIMESTAMP"

UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ReleaseIdentity:
    """Everything needed to say exactly what code is running."""

    version: str
    revision: str
    #: ``True`` when the checkout had uncommitted changes at build time. An
    #: instance reporting ``dirty`` is not reproducible from any commit, which
    #: disqualifies it from production.
    dirty: bool
    build_timestamp: str | None
    api_version: str
    schema_version: int
    audit_payload_version: int

    @property
    def label(self) -> str:
        """Compact form recorded on every audit entry, e.g. ``0.1.0+g1a2b3c4``.

        Bounded to 40 characters so it fits the ledger column without
        truncation, which would make it useless for matching.
        """
        if self.revision == UNKNOWN:
            return self.version
        suffix = f"+g{self.revision[:7]}"
        if self.dirty:
            suffix += ".dirty"
        return f"{self.version}{suffix}"[:40]

    def as_dict(self) -> dict:
        return {**asdict(self), "label": self.label}


def _git(*args: str) -> str | None:
    """Ask git, but only in a real checkout and never fatally."""
    repo_root = Path(__file__).resolve().parents[2]
    if not (repo_root / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


@lru_cache
def release_identity() -> ReleaseIdentity:
    """Resolve once per process; the answer cannot change while running."""
    revision = os.environ.get(REVISION_ENV_VAR, "").strip()
    dirty = False

    if revision:
        # A pipeline-supplied revision is authoritative and is trusted as-is;
        # a build system that stamps a dirty tree must say so itself.
        dirty = revision.endswith(".dirty")
        revision = revision.removesuffix(".dirty")
    else:
        revision = _git("rev-parse", "HEAD") or UNKNOWN
        if revision != UNKNOWN:
            dirty = bool(_git("status", "--porcelain"))

    return ReleaseIdentity(
        version=__version__,
        revision=revision,
        dirty=dirty,
        build_timestamp=os.environ.get(BUILD_TIMESTAMP_ENV_VAR) or None,
        api_version=API_VERSION,
        schema_version=SCHEMA_VERSION,
        audit_payload_version=AUDIT_PAYLOAD_VERSION,
    )


def version_label() -> str:
    """The string stamped onto audit entries and ledger anchors."""
    return release_identity().label
