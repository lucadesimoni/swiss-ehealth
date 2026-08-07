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
this project is at `0.1.0`.

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
make verify-version          # version consistency across the three files
make test                    # the full suite, including the version checks
# update CHANGELOG.md: move Unreleased items under the new version + date
make release VERSION=0.2.0   # re-checks, then creates the annotated tag
git push origin main --follow-tags
```

`make release` refuses if the working tree is dirty, if the version in
`version.py` does not match `VERSION`, if `CHANGELOG.md` has no section for it,
or if the tag already exists.

**Tags are annotated, never lightweight** — an annotated tag carries its own
author, date and message, and is itself an object in the repository, which a
lightweight tag is not. Sign them (`git config tag.gpgSign true`) where the
deployment requires signed provenance.

**Tags are never moved or deleted.** A published tag is a claim about what was
released; re-pointing it makes every audit statement that references it false.
A mistake gets a new version, never a corrected tag.

## Database migrations

`SCHEMA_VERSION` is bumped by every migration and reported by `GET /version`, so
a running instance states which schema it expects. Migrations themselves are not
yet wired up (see the gaps in the README) — `create_all` covers development, and
production will need Alembic. The constraint naming convention in `db.py` is
already set up for it, so migrations can address constraints by name rather than
by whatever the database happened to call them.

## What this buys an auditor

- Any record → the build that wrote it → the commit → the source.
- Any released version → its CHANGELOG entry, its four compatibility numbers,
  and its annotated tag.
- Any ledger range → verified or a named reason why not, with no silent
  "cannot check" case.
- Any deployment → whether it is running released, reproducible code.
