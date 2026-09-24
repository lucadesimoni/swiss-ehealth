# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""What this system is made of, and what each part promises.

``version.py`` answers "what is running". It cannot answer "what changed for
*me*". A clinic integrating only the medication module has no way to tell, from
``0.5.0 → 0.6.0``, whether anything it depends on moved: the software version
covers everything, so it warns about everything, which is the same as warning
about nothing.

Three tiers, because a change in each breaks a different set of people:

===========  ================================================================
``platform`` The runtime foundation — configuration names, database wiring,
             process startup, the schema guard, the shared API scaffolding.
             A breaking change here breaks *every* module and the deployment
             that runs them.
``core``     The domain kernel — AHVN13-derived UIDs, identity rules, crypto,
             capability tokens, and the ORM models every module stores through.
             A breaking change here breaks every module, and can invalidate
             material already issued: a stored token, a derived UID.
``module``   One functional capability, with its own HTTP surface. A breaking
             change here breaks that module's clients and nobody else's.
===========  ================================================================

The tiers are ordered by blast radius, and that ordering is the useful part: a
module MAJOR is a conversation with one integrator, a core MAJOR is a
conversation with all of them.

**Why the versions live in a dict and not on the dataclass.**
:data:`COMPONENT_VERSIONS` is a plain literal so that
``tests/test_components.py`` can read it *at a past commit* with
:mod:`ast` — parsed, never imported. Checking what a component declared two
years ago must not mean executing two-year-old code, and the assignment is the
fact being checked.

**Ownership is total and exclusive.** Every module under ``src/ehealth`` belongs
to exactly one component, and the suite fails if a file is owned twice or not
at all. Without that, a new file silently belongs to nothing and its changes
are covered by no component's version promise.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from functools import lru_cache

from ehealth.releases import ManifestError, repo_root, version_key

#: Layout of ``COMPONENTS.json``, so a future reshuffle of the file is
#: distinguishable from a corrupt one.
MANIFEST_VERSION = 1

MANIFEST_NAME = "COMPONENTS.json"

#: Blast radius, widest last. Used to order output and to reason about which
#: bump is the serious one.
TIERS = ("module", "core", "platform")

#: The declared version of every component. A plain dict literal on purpose —
#: see the module docstring. This is the single source of truth; the registry
#: below reads it, and the ledger is checked against it at each recorded commit.
COMPONENT_VERSIONS: dict[str, str] = {
    "platform": "0.2.0",
    "core": "0.2.0",
    "access": "0.1.0",
    "audit": "0.1.0",
    "auth": "0.2.0",
    "dossier": "0.1.0",
    "medication": "0.1.0",
    "offline": "0.1.0",
    "persons": "0.2.0",
    "interop": "0.1.0",
}


class ComponentError(ManifestError):
    """The component registry or its ledger is unusable or self-contradictory.

    A :class:`~ehealth.releases.ManifestError` subclass so that a caller which
    only cares that *some* ledger is unusable can catch the one exception, while
    a caller that distinguishes them still can.
    """


@dataclass(frozen=True, slots=True)
class Component:
    """One independently versioned part of the system.

    ``paths`` are relative to ``src/ehealth``. A trailing ``/`` claims a whole
    directory tree; anything else is one exact file.
    """

    name: str
    tier: str
    summary: str
    paths: tuple[str, ...]

    @property
    def version(self) -> str:
        return COMPONENT_VERSIONS[self.name]

    @property
    def ref_prefix(self) -> str:
        """Tag namespace. Modules are nested so ``git tag -l 'module/*'``
        lists exactly the modules, and no component tag can ever collide with
        a release tag (``v0.5.0``) or with another component's."""
        return f"module/{self.name}" if self.tier == "module" else self.name

    @property
    def tag(self) -> str:
        return f"{self.ref_prefix}/v{self.version}"

    def owns(self, relative_path: str) -> bool:
        return any(
            relative_path == path
            if not path.endswith("/")
            else relative_path.startswith(path)
            for path in self.paths
        )


#: The registry. Adding a file under ``src/ehealth`` without adding it here
#: fails ``test_every_file_is_owned_by_exactly_one_component``, which is the
#: point: an unowned file is covered by no compatibility promise.
COMPONENTS: tuple[Component, ...] = (
    Component(
        name="platform",
        tier="platform",
        summary=(
            "Configuration, database wiring, dependency container, process "
            "startup, the schema boot guard, and the release/component ledgers."
        ),
        paths=(
            "__init__.py",
            "config.py",
            "container.py",
            "db.py",
            "main.py",
            "schema.py",
            "version.py",
            "releases.py",
            "components.py",
            "api/__init__.py",
            "api/deps.py",
            "api/schemas.py",
            "services/__init__.py",
            "scripts/",
        ),
    ),
    Component(
        name="core",
        tier="core",
        summary=(
            "AHVN13-derived UIDs, identity rules, crypto and key handling, "
            "capability tokens, MFA, OIDC, and the ORM models every module "
            "stores through."
        ),
        paths=("domain/", "security/", "models/"),
    ),
    Component(
        name="persons",
        tier="module",
        summary="Person records, multi-role persons, and their identifiers.",
        paths=("services/persons.py", "api/routes_persons.py"),
    ),
    Component(
        name="interop",
        tier="module",
        summary=(
            "Patient identity lookups for other EPD systems: IHE PIXm "
            "(ITI-83) and PDQm (ITI-78) as FHIR, per the CH EPR FHIR guide."
        ),
        paths=(
            "services/patient_directory.py",
            "api/routes_fhir.py",
            "api/routes_mhd.py",
            "api/routes_atc.py",
        ),
    ),
    Component(
        name="dossier",
        tier="module",
        summary="The patient dossier and its documents.",
        paths=(
            "services/dossier.py",
            "services/blobstore.py",
            "services/retention.py",
            "api/routes_dossier.py",
        ),
    ),
    Component(
        name="medication",
        tier="module",
        summary="Medication entries and the medication list.",
        paths=("services/medication.py", "api/routes_medication.py"),
    ),
    Component(
        name="access",
        tier="module",
        summary=(
            "Access policy, consent, emergency access, and the capability "
            "grants that carry them."
        ),
        paths=("services/access.py", "api/routes_access.py"),
    ),
    Component(
        name="audit",
        tier="module",
        summary=(
            "The tamper-evident audit ledger, per-row change tracking, and the "
            "operations endpoints that report and verify them."
        ),
        paths=(
            "services/audit.py",
            "services/changelog.py",
            "api/routes_audit.py",
        ),
    ),
    Component(
        name="offline",
        tier="module",
        summary="Offline patient access and the synchronisation protocol.",
        paths=(
            "services/offline.py",
            "services/sync.py",
            "api/routes_offline.py",
        ),
    ),
    Component(
        name="auth",
        tier="module",
        summary="Authentication, sessions, and credential handling.",
        paths=("services/auth.py", "api/routes_auth.py"),
    ),
)


def _validate_registry() -> None:
    """Contradictions that would otherwise be discovered by a confused reader."""
    names = [component.name for component in COMPONENTS]
    if len(names) != len(set(names)):
        raise ComponentError("a component is declared twice")

    for component in COMPONENTS:
        if component.tier not in TIERS:
            raise ComponentError(
                f"{component.name}: unknown tier {component.tier!r}, "
                f"expected one of {list(TIERS)}"
            )
        if component.name not in COMPONENT_VERSIONS:
            raise ComponentError(f"{component.name} has no declared version")
        version_key(component.version)

    declared_only = set(COMPONENT_VERSIONS) - set(names)
    if declared_only:
        raise ComponentError(
            f"COMPONENT_VERSIONS declares versions for components that do not "
            f"exist: {sorted(declared_only)}"
        )

    for tier in ("platform", "core"):
        matching = [c.name for c in COMPONENTS if c.tier == tier]
        if matching != [tier]:
            raise ComponentError(
                f"the {tier} tier must hold exactly one component named "
                f"{tier!r}, found {matching}"
            )


_validate_registry()


def components_by_tier() -> tuple[Component, ...]:
    """Widest blast radius first, then alphabetical — the order a reader wants."""
    return tuple(
        sorted(COMPONENTS, key=lambda c: (-TIERS.index(c.tier), c.name)),
    )


def find_component(name: str) -> Component | None:
    for component in COMPONENTS:
        if component.name == name:
            return component
    return None


def component_versions() -> dict[str, str]:
    """What a running instance reports, so an integrator can ask one endpoint
    instead of reading a diff."""
    return {component.name: component.version for component in components_by_tier()}


def owner_of(relative_path: str) -> Component | None:
    for component in COMPONENTS:
        if component.owns(relative_path):
            return component
    return None


# --------------------------------------------------------------------------
# The component ledger
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComponentRelease:
    """One released component version, bound to the commit it was cut from.

    ``software_version`` is the ``__version__`` in force at that commit. It is
    a cross-reference, not a dependency: a module may be released between
    software releases, and then this names the version it was cut against.
    """

    component: str
    tier: str
    version: str
    commit: str
    tag: str
    date: str
    software_version: str

    @property
    def short_commit(self) -> str:
        return self.commit[:7]


def parse_manifest(raw: str) -> tuple[ComponentRelease, ...]:
    """Parse and validate the component ledger, in file order.

    Order is meaningful and is checked rather than repaired: sorting a
    contradictory file would hide the contradiction.
    """
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ComponentError(f"{MANIFEST_NAME} is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise ComponentError(f"{MANIFEST_NAME} must contain an object")

    declared = document.get("manifest_version")
    if declared != MANIFEST_VERSION:
        raise ComponentError(
            f"{MANIFEST_NAME} declares manifest_version {declared!r}, "
            f"this build understands {MANIFEST_VERSION}"
        )

    entries = document.get("component_releases")
    if not isinstance(entries, list):
        raise ComponentError(f"{MANIFEST_NAME} has no component_releases list")

    releases: list[ComponentRelease] = []
    fields = set(ComponentRelease.__dataclass_fields__)
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ComponentError(
                f"component release at position {position} is not an object"
            )
        missing = fields - set(entry)
        if missing:
            raise ComponentError(
                f"component release at position {position} is missing {sorted(missing)}"
            )
        unexpected = set(entry) - fields
        if unexpected:
            raise ComponentError(
                f"component release at position {position} has unknown keys "
                f"{sorted(unexpected)}"
            )
        releases.append(ComponentRelease(**entry))

    _check_ledger_invariants(tuple(releases))
    return tuple(releases)


def _check_ledger_invariants(releases: tuple[ComponentRelease, ...]) -> None:
    """An empty ledger is legitimate — the registry can declare a component
    before it has ever been cut. Everything else must hold."""
    latest_per_component: dict[str, ComponentRelease] = {}

    for release in releases:
        if len(release.commit) != 40 or not all(
            character in "0123456789abcdef" for character in release.commit
        ):
            raise ComponentError(
                f"{release.component} {release.version}: commit must be a full "
                f"40-character SHA, got {release.commit!r}"
            )

        component = find_component(release.component)
        if component is None:
            raise ComponentError(
                f"{MANIFEST_NAME} records {release.component!r}, which is not "
                f"a component of this system"
            )
        if release.tier != component.tier:
            raise ComponentError(
                f"{release.component} {release.version}: recorded tier "
                f"{release.tier!r} but the registry says {component.tier!r}"
            )

        expected_tag = f"{component.ref_prefix}/v{release.version}"
        if release.tag != expected_tag:
            raise ComponentError(
                f"{release.component} {release.version}: tag is "
                f"{release.tag!r}, expected {expected_tag!r}"
            )

        previous = latest_per_component.get(release.component)
        if previous is not None:
            if version_key(release.version) <= version_key(previous.version):
                raise ComponentError(
                    f"{release.component} {release.version} does not come "
                    f"after {previous.version}; the ledger is in release order "
                    f"and is append-only"
                )
            if release.commit == previous.commit:
                raise ComponentError(
                    f"{release.component}: {previous.version} and "
                    f"{release.version} both name commit "
                    f"{release.short_commit} — two versions cannot be the "
                    f"same code"
                )
        latest_per_component[release.component] = release


@lru_cache
def load_manifest() -> tuple[ComponentRelease, ...]:
    """The component ledger for this checkout.

    Raises rather than returning empty when the file is absent: a build that
    cannot state its component history should say so, not imply there is none.
    An *empty but present* ledger is a different, legitimate answer.
    """
    path = repo_root() / MANIFEST_NAME
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ComponentError(f"cannot read {path}: {exc}") from exc
    return parse_manifest(raw)


def releases_of(name: str) -> tuple[ComponentRelease, ...]:
    return tuple(entry for entry in load_manifest() if entry.component == name)


def latest_release_of(name: str) -> ComponentRelease | None:
    found = releases_of(name)
    return found[-1] if found else None


def find_component_release(name: str, version: str) -> ComponentRelease | None:
    for entry in releases_of(name):
        if entry.version == version:
            return entry
    return None


def unreleased_components() -> tuple[Component, ...]:
    """Components whose currently declared version is not in the ledger yet."""
    return tuple(
        component
        for component in components_by_tier()
        if find_component_release(component.name, component.version) is None
    )


def render_manifest(releases: tuple[ComponentRelease, ...], note: str) -> str:
    """Serialise the ledger back to the exact on-disk form.

    Byte-stable so that recording a component release produces a one-entry
    diff and nothing else.
    """
    document = {
        "$schema_note": note,
        "manifest_version": MANIFEST_VERSION,
        "component_releases": [
            {
                "component": release.component,
                "tier": release.tier,
                "version": release.version,
                "commit": release.commit,
                "tag": release.tag,
                "date": release.date,
                "software_version": release.software_version,
            }
            for release in releases
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def declared_versions_in(source: str) -> dict[str, str]:
    """Read :data:`COMPONENT_VERSIONS` out of a ``components.py`` *source
    string* without importing it.

    Parsed with :mod:`ast`, never executed: checking what a component declared
    at a past commit must not mean running that commit's code.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise ComponentError(f"cannot parse components.py: {exc}") from exc

    for node in tree.body:
        targets = (
            [node.target]
            if isinstance(node, ast.AnnAssign)
            else node.targets
            if isinstance(node, ast.Assign)
            else []
        )
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "COMPONENT_VERSIONS":
                if node.value is None:
                    continue
                try:
                    value = ast.literal_eval(node.value)
                except ValueError as exc:
                    raise ComponentError(
                        f"COMPONENT_VERSIONS is not a literal: {exc}"
                    ) from exc
                if not isinstance(value, dict):
                    raise ComponentError("COMPONENT_VERSIONS is not a dict")
                return value

    raise ComponentError("components.py declares no COMPONENT_VERSIONS")
