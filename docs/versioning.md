# Versioning and release policy

An electronic patient record keeps data for twenty years. Long after a release
is gone, someone has to be able to ask of a single record: *which code wrote
this, under which rules, and can I still verify it?* This document is how that
question stays answerable.

## Five version numbers, not one

Conflating them is the usual failure. A patch release that quietly changes the
signed audit payload makes every earlier ledger entry unverifiable, and nobody
finds out until an audit.

| Number | Source of truth | Bumped when | Breaks |
|---|---|---|---|
| **Software version** | `src/ehealth/version.py:__version__` | every release | nothing by itself — it *describes* |
| **API version** | `version.py:API_VERSION` | breaking HTTP change | every client |
| **DB schema version** | `version.py:SCHEMA_VERSION` | every migration | the database; needs a migration |
| **Audit payload version** | `version.py:AUDIT_PAYLOAD_VERSION` | signed-payload layout change | verification of *old* entries, unless the old builder is kept |
| **Key versions** | `KeyRing`, per purpose | key rotation | nothing — old material stays verifiable |
| **Component versions** | `components.py:COMPONENT_VERSIONS` | that component's surface changes | only that component's consumers — see [Components](#components-module-core-platform) |

`src/ehealth/version.py` is the single source of truth for the first four.
`pyproject.toml` and `CHANGELOG.md` are checked against `__version__` by
`tests/test_versioning.py`, so the three cannot drift apart — a release with a
mismatched version number fails the test suite rather than shipping.

## Semantic versioning, scoped

`MAJOR.MINOR.PATCH`, where the public surface is: the HTTP API, the token
format, the signed audit payload, the database schema, and the configuration
variable names.

- **MAJOR** — a client, a stored token, or an existing ledger entry stops
  working. Removing an endpoint or field, tightening validation, changing a
  token's meaning, dropping support for an audit payload version.
- **MINOR** — new capability, everything that worked still works. New endpoints
  or optional fields, new scopes, a new key version, a DB migration that is
  additive.
- **PATCH** — bug and security fixes with no surface change.

Anything below `1.0.0` may break on a MINOR bump; that is the SemVer bargain and
this project is pre-`1.0.0`. `make releases` prints where it currently stands.

## Components: module, core, platform

The software version covers everything, so it warns about everything, which is
the same as warning about nothing. A clinic integrating only the medication
module cannot tell from `0.5.0 → 0.6.0` whether anything it depends on moved.

So the parts version independently, in three tiers ordered by **blast radius**:

| Tier | What it is | A breaking change breaks |
|---|---|---|
| `platform` | Configuration names, database wiring, the container, process startup, the schema boot guard, the shared API scaffolding, both ledgers | every module, and the deployment running them |
| `core` | AHVN13-derived UIDs, identity rules, crypto and keys, capability tokens, MFA, OIDC, and the ORM models every module stores through | every module — and material already issued: a stored token, a derived UID |
| `module` | One capability with its own HTTP surface: `persons`, `dossier`, `medication`, `access`, `audit`, `offline`, `auth` | that module's clients, and nobody else's |

That ordering is the useful part. A module MAJOR is a conversation with one
integrator; a core MAJOR is a conversation with all of them.

`src/ehealth/components.py` is the single source of truth. `COMPONENT_VERSIONS`
is a plain dict literal so the suite can read it *at a past commit* with `ast` —
parsed, never imported, because verifying what a component declared two years
ago must not mean executing two-year-old code.

**Models are core; the services over them are modules.** `models/audit.py` is
kernel — every module stores through it — while `services/audit.py` is the audit
module's own logic. Getting that split wrong is what makes tiers decorative.

**Ownership is total and exclusive.** Every `.py` file under `src/ehealth`
belongs to exactly one component, and
`test_every_file_is_owned_by_exactly_one_component` fails if a file is owned
twice or not at all. A file owned by nothing is covered by no version promise,
and nobody notices, because nothing breaks until an integrator trusts a version
that never accounted for it. Adding a file therefore means naming its owner.

`GET /v1/version` reports `components`, so an integrator asks one endpoint
instead of reading a diff. It is behind the admin key with the rest of the
build provenance: knowing which module versions are deployed narrows an
attacker's search the same way the revision does.

### Component tags

Namespaced, so a component tag can never be mistaken for a release tag or for
another component's:

```
platform/v0.1.0
core/v0.1.0
module/persons/v0.1.0      # git tag -l 'module/*' lists exactly the modules
```

The rules that apply to release tags apply here unchanged: **annotated, never
lightweight; never moved; never deleted.**

**Where the numbers start.** Every component starts at `0.1.0`, declared at
software release 0.6.0. They do not reach back over 0.1.0–0.5.0: component
boundaries were not declared then, so any earlier per-component number would be
a retrofitted guess. Before 0.6.0 the software version is the only honest
description, and after it each component moves on its own.

## The release ledger

`RELEASES.json` records, for every released version, the commit it was cut
from and the four compatibility numbers that commit declared.

```json
{ "version": "0.4.0", "commit": "8670e937a7af…", "tag": "v0.4.0",
  "date": "2026-08-09", "api_version": "v1",
  "schema_version": 4, "audit_payload_version": 2 }
```

**Why a file and not just the tag.** An annotated tag is the conventional
answer to "what is 0.3.0?", and this project cuts one for every release. But a
tag is a mutable pointer that lives *beside* the history rather than in it. It
can be moved, deleted, or never reach the remote at all — protected-ref rules,
restricted CI networks and locked-down mirrors all routinely refuse
`refs/tags/*` while accepting `refs/heads/*`. A clone that arrives without tags
then has no record of which commit was released, and commit subjects are prose,
not evidence. `RELEASES.json` is an ordinary file in the tree: every clone
carries it, git hashes it, and the history shows exactly when each entry was
added and by whom.

Tags remain the ergonomic handle. The ledger is the durable one, and
`tests/test_releases.py` requires the two to agree wherever both are present —
a tag pointing somewhere other than its ledger entry fails the suite.

**What makes an entry trustworthy.** Not that it parses — anyone can write a
plausible SHA. `test_every_entry_matches_its_commit` reads
`src/ehealth/version.py` *at each recorded commit* and requires it to declare
exactly the numbers the entry claims. An invented, mistyped or stale SHA fails
there. The ledger also refuses, at parse time, an abbreviated SHA, a repeated
version, two versions sharing a commit, out-of-order entries, and a schema or
audit-payload version that goes backwards — each of which would otherwise be a
silent falsehood about what shipped.

**The ledger is append-only.** An entry, once committed, is never edited or
removed, for the same reason a tag is never moved: it is a claim about what was
released, and correcting it retroactively makes every audit statement that
referenced it false. A mistake gets a new version.

Where a deployment needs cryptographic rather than procedural provenance, sign
the tags (`git config tag.gpgSign true`) and sign the release commits. The
ledger records what was released; a signature is what proves who said so.

### The component ledger

`COMPONENTS.json` is the same idea for components, for the same reason: the
component tags are the ergonomic handle, and a clone that arrives without
`refs/tags/*` would otherwise have no record of which commit a module version
was cut from.

```json
{ "component": "persons", "tier": "module", "version": "0.1.0",
  "commit": "…", "tag": "module/persons/v0.1.0",
  "date": "2026-08-10", "software_version": "0.6.0" }
```

`software_version` is the `__version__` in force at that commit — a
cross-reference, not a dependency. A module may be cut between software
releases, and then this records which version it was cut against.

The checks mirror the release ledger's, and one of them is the same
load-bearing check: `test_every_entry_matches_its_commit` parses
`components.py` at the recorded commit and requires `COMPONENT_VERSIONS` to
declare exactly the version claimed. An invented or stale SHA fails there.

Two differences are deliberate:

- **An empty ledger is legitimate.** The release ledger refuses to be empty —
  a build that cannot state its release history should say so. But the registry
  may declare a component before it has ever been cut, and `make components`
  reports that as `not yet` rather than pretending otherwise.
- **Versions are per-component, not global.** Two components may share a
  commit — the baseline is every component cut from one — while one component
  may not have two versions at the same commit. A global "one version per
  commit" rule would forbid the normal case.

## The audit payload rule

**`_payload_v1` in `services/audit.py` is never edited after a release.**

Its output is hashed and signed. Changing one field name changes the hash of
every entry ever written under it, and they all start failing verification —
which looks exactly like tampering. A new layout is:

1. a new `_payload_v2` function,
2. a new entry in `PAYLOAD_BUILDERS`,
3. a bump of `AUDIT_PAYLOAD_VERSION`,
4. **the old builder left in place, forever.**

Each entry records the version it was written under, so verification picks the
right builder. A build that meets a payload version it does not know reports
`ok: false` with a reason naming the version — it fails closed rather than
declaring an entry sound that it cannot actually check.

## Tracing a record to its code

Every ledger entry and every anchor carries `software_version` — the same
`label` that `GET /version` reports, e.g. `0.1.0+g1a2b3c4`. It is inside the
signed payload, so it cannot be changed after the fact.

```bash
# what is running
curl -H "X-Admin-Key: $KEY" https://dossier.example.ch/version

# what wrote a given record — the label is on the audit entry
curl -H "X-Admin-Key: $KEY" https://dossier.example.ch/audit/verify

# the exact source, from the revision the label carries
git checkout g1a2b3c4   # or: git show v0.1.0
```

A `label` ending in `.dirty` means the build came from a checkout with
uncommitted changes. It is not reproducible from any commit and **must not run
in production** — treat it as a finding.

`revision` comes from `EHEALTH_GIT_REVISION`, which the build pipeline sets. In
a working checkout it falls back to asking git; if neither is available it
reports `unknown` rather than guessing, because a wrong revision is worse than
no revision.

## Release procedure

```bash
# 1. bump __version__ in src/ehealth/version.py and pyproject.toml
# 2. move the Unreleased items in CHANGELOG.md under the new version + date,
#    and add the compatibility row
git commit -am "Release 0.5.0"

make release VERSION=0.5.0   # full suite, then the annotated tag on that commit
make record-release          # appends the entry for HEAD to RELEASES.json
git commit -m "Record release 0.5.0 in the ledger" RELEASES.json

git push -u origin main
git push origin v0.5.0
```

Two commits, deliberately. The tag and the ledger entry both name the *release*
commit, and a commit's hash cannot be known before the commit exists — so the
entry that records it necessarily lands one commit later. `git describe` on
`main` then reads `v0.5.0-1-g…`, which is correct: main is one commit past the
release.

`make release` refuses if the working tree is dirty, if the version in
`version.py` does not match `VERSION`, if `CHANGELOG.md` has no section for it,
if the tag already exists, or if the ledger already records that version.
`make record-release` refuses on a dirty tree — the recorded commit would not
describe what is on disk — and refuses to overwrite an existing entry.

**The tag push is the step that can fail**, and it fails independently of
everything else: protected-ref rules and restricted egress commonly allow
`refs/heads/*` and refuse `refs/tags/*`. When that happens the release is still
fully recorded, because `RELEASES.json` went out with the branch push. Push the
tag later from a machine that can, and the ledger will already say where it
belongs — `test_tags_agree_with_the_ledger_where_they_exist` then checks it
landed on the right commit.

**Tags are annotated, never lightweight** — an annotated tag carries its own
author, date and message, and is itself an object in the repository, which a
lightweight tag is not.

**Tags are never moved or deleted.** A published tag is a claim about what was
released; re-pointing it makes every audit statement that references it false.
A mistake gets a new version, never a corrected tag.

### Cutting a component

A component moves on its own schedule, so this is not tied to a software
release:

```bash
# 1. bump the component in COMPONENT_VERSIONS in src/ehealth/components.py
git commit -am "medication 0.2.0: optional dosage field"

make release-component COMPONENT=medication   # full suite, then the tag
make record-component-release COMPONENT=medication
git commit -m "Record medication 0.2.0 in the ledger" COMPONENTS.json

git push -u origin main
git push origin module/medication/v0.2.0
```

The same two-commit shape as a software release, for the same reason: the tag
and the ledger entry both name the commit that carries the version, and a
commit's hash cannot be known before the commit exists.

`make release-component` refuses on a dirty tree, an unknown component, an
existing tag, or a version already in the ledger. `make record-component-release`
with no `COMPONENT=` records every component whose declared version is not in
the ledger yet, which is what cutting the baseline needs.

Whether a component bump also warrants a software release is a judgement call:
the software version describes the whole tree, so it moves when the tree ships,
not every time a module's number changes.

## Database migrations

`SCHEMA_VERSION` is bumped by every migration and reported by `GET /v1/version`,
so a running instance states which schema it expects. Alembic carries the
changes and a boot guard refuses to serve a schema this build does not expect,
in both directions — see [`migrations.md`](migrations.md).

The ledger checks one thing the migrations cannot: that schema versions across
releases form an unbroken run. A gap would mean some deployment has no upgrade
path to the next version.

## What this buys an auditor

- Any record → the build that wrote it → the commit → the source.
- Any released version → its CHANGELOG entry, its four compatibility numbers,
  its commit, and its annotated tag — with the commit recorded inside the
  repository, so it survives a clone that has no tags.
- Any component → which version of it is deployed, which commit that version
  was cut from, and which files it covers — so "did the part I integrate
  against change?" is answerable without reading a diff.
- Any ledger range → verified or a named reason why not, with no silent
  "cannot check" case.
- Any deployment → whether it is running released, reproducible code.

## What this does not buy

The release ledger is a *procedural* record, not a cryptographic one. It is
committed by whoever cuts the release, and anyone who can push to `main` can
append a plausible-looking entry — the checks catch entries that contradict the
repository, not an attacker who tampers consistently. Signed commits and signed
tags, plus branch protection requiring review, are what turn this into evidence
against a hostile maintainer. Neither is enabled here.
