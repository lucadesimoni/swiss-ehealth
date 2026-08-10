# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
as scoped in [`docs/versioning.md`](docs/versioning.md).

Each released version below states the four compatibility numbers in force for
that release, so a deployment can be matched against its data without reading
the diff:

| | API | DB schema | Audit payload |
|---|---|---|---|
| 0.6.0 | v1 | 4 | 2 |
| 0.5.0 | v1 | 4 | 2 |
| 0.4.0 | v1 | 4 | 2 |
| 0.3.0 | v1 | 3 | 2 |
| 0.2.0 | v1 | 2 | 1 |
| 0.1.0 | v1 | 1 | 1 |

## [Unreleased]

### Fixed

`make record-component-release` took the recorded commit from `HEAD`, which is
only correct when it runs before any further commit. Cutting the 0.6.0 baseline
showed why that is too fragile: two ledgers cannot both be recorded from a clean
tree in one commit — whichever runs second sees the first one's edit — so the
component ledger would have named the commit that *records* the release instead
of the one the tags point at, and
`test_tags_agree_with_the_ledger_where_they_exist` would have failed.

The commit now comes from the component's annotated tag, which is by definition
the statement of where that version was cut, so the ledger and the tag cannot
disagree. `software_version` is likewise read from `version.py` at that commit
rather than off the disk. The dirty-tree guard now applies only to the `HEAD`
fallback, which is the only path where the commit is inferred from what is on
disk.

## [0.6.0] — 2026-08-10

Nothing in this release changes the database schema, the API contract or the
signed audit payload. It changes what the version numbers are *able to say*.

### Added

**The parts are versioned, not just the whole.** Until now one number covered
everything, so it warned about everything — which is the same as warning about
nothing. A clinic integrating only the medication module could not tell from
`0.5.0 → 0.6.0` whether anything it depended on had moved.

`src/ehealth/components.py` declares three tiers, ordered by blast radius:

- **`platform`** — configuration names, database wiring, the container, process
  startup, the schema boot guard, the shared API scaffolding, both ledgers. A
  breaking change here breaks every module and the deployment running them.
- **`core`** — AHVN13-derived UIDs, identity rules, crypto and keys, capability
  tokens, MFA, OIDC, and the ORM models every module stores through. A breaking
  change here can invalidate material already issued: a stored token, a derived
  UID.
- **`module`** — one capability with its own HTTP surface: `persons`, `dossier`,
  `medication`, `access`, `audit`, `offline`, `auth`. A breaking change here
  breaks that module's clients and nobody else's.

That ordering is the useful part: a module MAJOR is a conversation with one
integrator, a core MAJOR is a conversation with all of them. Models are core
while the services over them are modules — `models/audit.py` is kernel,
`services/audit.py` is the audit module — because getting that split wrong is
what makes tiers decorative.

Every component starts at `0.1.0`, declared here. The numbers do not reach back
over 0.1.0–0.5.0: component boundaries were not declared then, so any earlier
per-component number would be a retrofitted guess.

**Ownership is total and exclusive.** Every `.py` file under `src/ehealth`
belongs to exactly one component, and the suite fails if a file is owned twice
or not at all — a file owned by nothing is covered by no version promise, and
nothing breaks until an integrator trusts a version that never accounted for it.
Adding a file now means naming its owner.

**The component ledger** — `COMPONENTS.json` records, for every released
component version, the commit it was cut from, its tier, its tag and the
software version in force at that commit. Same reasoning as `RELEASES.json`:
tags are the ergonomic handle, and a clone that arrives without `refs/tags/*`
would otherwise have no record of which commit a module version came from.

Entries are checked against the repository rather than merely parsed: the suite
parses `src/ehealth/components.py` at each recorded commit with `ast` and
requires `COMPONENT_VERSIONS` to declare exactly the version claimed. It parses
rather than imports, because verifying what a component declared two years ago
must not mean executing two-year-old code.

Two invariants differ from the release ledger, deliberately: an empty ledger is
legitimate, because the registry may declare a component before it has ever been
cut; and versions are per-component, so two components may share a commit — the
baseline is every component cut from one — while one component may not have two
versions at the same commit.

**Component tags are namespaced** so none can be mistaken for a release tag or
for another component's: `platform/v0.1.0`, `core/v0.1.0`,
`module/persons/v0.1.0`. `git tag -l 'module/*'` lists exactly the modules. The
existing rules hold unchanged — annotated, never lightweight; never moved; never
deleted.

**`GET /v1/version` reports `components`**, so an integrator asks one endpoint
instead of reading a diff. It stays behind the admin key with the rest of the
build provenance: knowing which module versions are deployed narrows an
attacker's search the same way the revision does.

- `make components` prints the registry and whether each declared version has
  been cut.
- `make release-component COMPONENT=<name>` runs the suite and cuts the tag.
- `make record-component-release` appends to the ledger.
- `make verify-version` now covers the component registry and its ledger too.

### Fixed

**The release tags v0.1.0–v0.5.0 now exist as annotated tag objects.** The
ledger had recorded them since 0.5.0 and `RELEASES.json` named the right
commits, but no tag object had ever been created in the repository, so
`test_tags_agree_with_the_ledger_where_they_exist` had nothing to compare and
skipped every entry. Each tag now points at the commit its ledger entry
records, with its tagger date set to that commit's date rather than to the day
it was reconstructed.

## [0.5.0] — 2026-08-10

Nothing in this release changes the database schema, the API or the signed
audit payload. It changes what is *checked* — several things this
repository asserted were true had never been run.

### Added

**The release ledger** — `RELEASES.json` records, for every released version,
the commit it was cut from and the four compatibility numbers that commit
declared. Until now that binding existed only as an annotated tag, and a tag is
a mutable pointer beside the history rather than in it: protected-ref rules and
restricted egress routinely accept `refs/heads/*` and refuse `refs/tags/*`, and
a clone that arrives without tags then cannot say which commit was released.
The ledger is an ordinary file in the tree, so every clone carries it.

Entries are checked against the repository rather than merely parsed: the suite
reads `src/ehealth/version.py` at each recorded commit and requires it to
declare exactly the numbers claimed, so an invented, mistyped or stale SHA
fails. Verified against real tampering — pointing an entry at an unrelated real
commit makes it fail with the discrepancy named.

Parse-time invariants refuse an abbreviated SHA, a repeated version, two
versions sharing a commit, out-of-order entries, and a schema or audit-payload
version that goes backwards. Where a tag is present it must agree with the
ledger; where it is absent the ledger stands alone.

- `make releases` prints the ledger.
- `make record-release` appends the current commit.
- `make verify-version` now covers the ledger as well as the three files.

**PostgreSQL is now actually tested.** `EHEALTH_TEST_DATABASE_URL` points the
whole suite at PostgreSQL, one schema per test. Previously every claim about
PostgreSQL rested on a SQLite run: 439 tests now pass against PostgreSQL 16,
including the migration drift check, which reports zero differences against
real reflected types.

**A migration concurrency guard.** `alembic upgrade head` takes a PostgreSQL
advisory lock and refuses a second migrator immediately rather than leaving it
to block. A retried pipeline or a two-region rolling deploy starts two
migrations by default; without the lock both run and the loser fails partway
through. `EHEALTH_MIGRATION_LOCK_TIMEOUT` (default `5s`) bounds how long a
migration waits for a table lock — the setting that separates a slow deploy
from an outage, because every query queues behind a waiting `ALTER TABLE`.

**CI** — lint, the suite on SQLite, the suite on PostgreSQL 16 with a bare
`alembic upgrade head` run twice to prove a redeploy is a no-op, and a Docker
build that is then started to check it runs as uid 10001 and carries the
revision the pipeline stamped. The repository had no pipeline at all; "runs on
PostgreSQL" and "the image builds" were true only as far as anyone had tried.

**Lint and format are enforced**, with a ruff configuration covering bugbear
and the bandit rules that matter here. The tree is now uniformly formatted;
before this, 37 of 63 files were not.

### Fixed

- **A migration that silently did nothing.** Taking the advisory lock opened an
  implicit transaction, which made alembic's own `begin_transaction()` nest
  inside it — so the migration never committed while every command still
  reported success, leaving an empty database. Caught by running the migration
  tests against PostgreSQL, which is exactly the class of failure SQLite cannot
  show. The lock and the timeouts are session-scoped, so committing before
  handing over to alembic is safe.
- **`docker compose up` could not start.** The app service waited only for the
  database to be healthy, never for migrations, so the schema guard refused to
  serve and the container restart-looped with an error that looked like an
  application bug. A `migrate` service now runs to completion first.
- **The suite only ran under `python -m pytest`.** Five test modules import
  shared constants from `tests.conftest`, which resolves only when the
  repository root is on the path — `python -m pytest` puts it there implicitly,
  a bare `pytest` does not. It passed through `make test` and failed for
  anyone invoking pytest directly. Found by CI on its first run.
- **A `%` in the database URL broke the migration tests** — `alembic.ini` is
  read by configparser, which treats `%` as interpolation. Any percent-encoded
  URL or password containing `%` hit it, and the error named configparser
  rather than the URL.
- **A closure over a loop variable** in ledger verification (`fail()` in
  `verify_chain`). Correct today because it is only called within its own
  iteration, but a verification failure reporting the wrong sequence number
  sends an auditor to the wrong record; the variables are now bound explicitly.
- **`zip()` without `strict=`** in the CHE-UID check-digit calculation, where a
  silently shortened sequence would compute a plausible but wrong check digit.

### Changed

- `make release` names the full sequence including the ledger commit, and says
  plainly that the tag push is the one step a restricted network can refuse.
- `docs/versioning.md` documents the ledger, the two-commit release procedure,
  and what the ledger does *not* prove: it is a procedural record, not a
  cryptographic one. Signed commits and tags plus branch protection are what
  make it evidence against a hostile maintainer, and neither is enabled here.
- `docs/migrations.md` replaces its "no PostgreSQL run, no zero-downtime
  tooling" section with what now exists, and narrows what is still missing to
  `CREATE INDEX CONCURRENTLY`, expand/contract enforcement, and an untested
  restore path.
- New: `make lint`, `make format`, `make test-postgres PGURL=…`.
- `psycopg` moved into a `postgres` extra rather than being assumed present.

## [0.4.0] — 2026-08-09

Closes the gap that made everything before it undeployable: there was no way to
change the schema of a database that already held data. API `v1`, DB schema
`4`, audit payload `2`.

### Added

**Migrations**
- Alembic, wired to the application's own settings so the connection string
  lives in exactly one place and there is no way to migrate one database while
  the application talks to another.
- An initial migration covering all 20 tables. It refuses to downgrade:
  dropping every table is not a rollback, it is data loss with extra steps.
- `make migrate`, `make migrate-status`, `make migration name="…"`.
- Custom column types render by name in migrations (`ehealth.models.base.JsonType`)
  rather than as an inlined expression needing three more imports.

**The drift test** — `tests/test_migrations.py::TestNoDrift` runs the
migrations on an empty database and asks alembic whether the result differs
from the models. Without it drift is silent: the suite builds its schema with
`create_all`, so a model change with no migration passes every test and only
breaks in production, where `create_all` never runs. Verified against real
drift — adding an undeclared model column makes it fail.

**The boot guard** — a new `schema_metadata` table records the schema version
and the build that applied it, and the application refuses to start against a
schema it does not expect, in **both** directions:
- database older than the code: migrations have not been run;
- database *newer* than the code: a rollback that skipped its migration. This
  is the direction people forget, and the dangerous one — the old build does
  not know about columns the new schema requires, so writing through it can
  drop data silently.

`create_all` stamps the version too, so the development path leaves a database
the guard accepts.

### Notes for existing deployments

A database created by 0.3.0 has no `alembic_version` and no `schema_metadata`.
Verify its shape matches the models, then `alembic stamp head` and add the
`schema_metadata` row before starting 0.4.0 — or, for a pre-production
deployment, recreate it.

**Not verified:** the migration was generated and applied on SQLite only.
Verify against PostgreSQL before production. There is also no zero-downtime
tooling yet — no advisory lock against two migrators racing, no statement
timeout, no `CREATE INDEX CONCURRENTLY`. See
[`docs/migrations.md`](docs/migrations.md).

## [0.3.0] — 2026-08-07

National scale, offline for patients, and an API partners can build on.
API `v1`, DB schema `3`, audit payload `2`.

Pre-1.0, so these breaking changes come on a MINOR bump — see
[`docs/versioning.md`](docs/versioning.md).

### Fixed

- **The audit ledger no longer serialises the whole country.** One global hash
  chain meant every append in the system contended for a single tail lock —
  the ceiling for a national deployment, reached long before anything else ran
  out. There is now **one chain per dossier** plus a `global` chain for
  everything not scoped to a patient, so two clinicians writing to two
  different patients never contend, while writes to the *same* patient still
  serialise, which is the ordering that matters clinically.

### Added

**Offline for patients**
- Signed **emergency dataset** — current medication and the identifying
  minimum, under 2 KB so it fits a QR code on a card. Carries only material
  the patient left at the `NORMAL` level: a bundle that leaves the system
  loses every access control the system has, so what the patient hid must not
  travel on a card they carry.
- Signed **full bundle** for the patient's own device, clamped to what the
  presenting capability actually reaches.
- `verify_bundle()` — a free function with no database, no settings and no
  container, so a phone, a paramedic's tablet or a partner system can check a
  bundle with nothing but the published public key. `GET /v1/offline/public-key`
  is deliberately unauthenticated for the same reason.
- Bundles name the ledger head they were cut from, so a holder can place one
  in the record's history against a published anchor, and carry an expiry:
  an expired bundle still *verifies*, and readers are told it is stale rather
  than being shown old data as current.
- **Offline capture sync** (`POST /v1/offline/sync`), idempotent per
  client-generated id so a phone that loses signal mid-upload can retry
  without duplicating, and reported per item so one bad row never blocks a
  patient's whole history. The device clock is recorded because it is
  clinically meaningful and never trusted for ordering.
- Prescriptions cannot be captured offline: that needs a licensed
  professional and a live licence check, neither of which happens on a phone
  in a tunnel.

**API-first**
- **BREAKING** — every resource route moves under `/v1`. A partner hard-coding
  a URL needs it to keep meaning the same thing, and a breaking change should
  arrive as `/v2` rather than as a surprise.
- Every error leaves as **RFC 9457 problem details**
  (`application/problem+json`) with a machine-readable `type`, so partners
  branch on a URI instead of parsing prose.
- `GET /v1/audit/verify?chain_id=…` verifies a single dossier — the question a
  patient actually has ("was *my* record tampered with"), and it stays cheap
  however large the system gets. `GET /v1/audit/verify-all` covers everything,
  as the background job it is at scale.

**Ledger**
- Audit payload **version 2** adds the chain id inside the signature, so an
  entry cannot be replayed into a different chain and still verify. Version 1
  entries keep verifying under their own builder, which is what the versioned
  payload design was built for.
- Anchors now commit **every chain that moved** into one Merkle root, with a
  per-chain checkpoint row only for chains with activity — so anchoring costs
  track activity rather than population. Anchors link to their predecessor and
  form their own chain, and `verify_anchor()` recomputes the root and
  signature from the checkpoints.
- Merkle construction is domain-separated between leaves and nodes, and
  carries an odd node up rather than duplicating it, avoiding the
  CVE-2012-2459 ambiguity where two leaf sets produce one root.

## [0.2.0] — 2026-08-07

Swiss identifiers corrected and completed, and one person can now hold several
roles. API `v1`, DB schema `2`, audit payload `1`.

Pre-1.0, so these breaking changes come on a MINOR bump — see
[`docs/versioning.md`](docs/versioning.md).

### Fixed

- **The EPR-SPID is 18 digits, not 13.** The patient identifier of the
  electronic patient record (`761…`) was being generated with 13 digits, the
  length of the AHVN13 it derives from. It is now 18, with a mod-10 check digit
  over fourteen significant digits — which also removes the collision pressure
  the 13 digit version had at population scale. The AHVN13 itself remains 13
  digits, as AHVG/AHVV define it.
- **A person can be both a physician and a patient.** `Person.kind` made role a
  property of the person, which forced anyone holding two roles into two
  records with two pseudonyms — so a doctor could not be seen as a patient by
  their own colleagues. Roles are now rows in `person_role`, each with its own
  validity and audit trail, and authority is a question asked of the database
  at the moment it matters.

### Changed

- **BREAKING** — person UIDs use the `per_` prefix. `pat_`, `hcp_` and `vis_`
  are gone: encoding a role in an identifier is exactly what stopped a person
  holding two.
- **BREAKING** — `PersonCreate` takes `roles: []` instead of `kind`, and no
  longer takes `gln`/`profession`/`organization_uid`; those move to the
  credential.
- **BREAKING** — `MedicinalProduct.prescription_only` and `narcotic` are
  replaced by `dispensing_category` (Swissmedic A/B/D/E, category C absent
  since its 2019 abolition) and `narcotic_schedule` (BetmVV-EDI annexes a–d).
- `AccessGrant.grantee_kind` now records the *role the grant was issued under*,
  so an access says in which capacity it was made.

### Added

**Swiss professional identification**
- `ProfessionalCredential`: GLN, the federal register the professional appears
  in (MedReg per MedBG art. 51 ff., NAREG per GesBG, PsyReg per PsyG), the
  cantonal practice licence with its validity, and the ZSR/RCC billing number —
  recorded separately because it grants invoicing authority, not clinical
  authority.
- Credential verification against a named source, recorded with evidence and a
  timestamp: "we were told" and "we checked" no longer look the same.
- Licence suspension, which removes prescribing authority immediately.

**Swiss medicinal product identification**
- Swissmedic authorisation number (HMG art. 9), validated and normalised;
  authorisation status and expiry, so a withdrawn product cannot be prescribed.
- Refdata Pharmacode, unique per product.
- ATC validated at every depth; GLN of the marketing authorisation holder.
- Spezialitätenliste flag and number (KVG art. 52).

**Prescribing authority, enforced at the write**
- A prescription or dispense requires an active professional role *and* a live
  cantonal licence for a profession that may prescribe (HMG art. 24 ff.).
  Patients may still record their own self-medication — a complete medication
  list is worth more than a tidy one.
- Every statement records the credential and GLN it was made under, copied
  rather than joined, so it stays attributable to the licence that was live at
  the time.
- Narcotic schedule and dispensing category land in the audit trail, making a
  BetmG audit a query rather than a reconstruction.

**Other identifiers**
- VeKa health insurance card number (20 digits, `80756…`), sealed like any
  other direct identifier. Format validation only — the check-digit scheme is
  documented as not implemented rather than guessed at.
- Institution GLN, ZSR and canton.

**Deployment**
- `Dockerfile`: two-stage, non-root (UID 10001), read-only-root-filesystem
  compatible, no compiler or package manager in the runtime image, build
  revision stamped in so `/version` and the ledger report a traceable commit.
- `compose.yaml`: Postgres, dropped capabilities, no-new-privileges, database
  not published to the host.
- `SECURITY.md`: threat model stating what is *not* covered — root key
  compromise, a live signing key, email as a second factor, availability.
- `docs/deployment-ch.md`: Swiss-operated providers, why a hyperscaler's Zurich
  region is not Swiss jurisdiction, key custody options, data residency
  enforced rather than assumed, and what to monitor.

## [0.1.0] — 2026-08-07

First release. API `v1`, DB schema `1`, audit payload `1`.

### Added

**Identity**
- AHVN13 (`756.…`) validation with EAN-13 check digit, and a `Ahvn13` type
  whose `repr` is masked so an accidental log statement cannot leak one.
- Derivation of a 256-bit pseudonymous person id (`ppid`), an allocated
  13-digit sector identifier (`761.…`, EPR-SPID shape) and a rotatable blind
  index. The AHV number itself is discarded, or kept only as an AEAD envelope
  bound to the pseudonym when `EHEALTH_STORE_SEALED_AHVN` is on.
- Controlled re-identification (`disclose_ahvn`) requiring a stated legal basis
  and auditing before decryption.
- Type-prefixed, time-sortable ULID-based UIDs for every entity; CHE-UID and
  GLN/GTIN validation.

**Access control**
- Capability tokens bound to one dossier, purpose, confidentiality ceiling and
  scope list, with a closed algorithm registry, versioned key ids, a database
  registry of every `jti` for revocation, optional proof-of-possession binding
  and a delegation chain.
- Consent model with participation status, default access level, per-person and
  per-institution rules where DENY beats ALLOW, `SECRET` clamped to
  patient-only, and emergency access capped below `SECRET`.
- Consent re-evaluated at every token use, not at issuance.
- Visitor grants: read-only, time-boxed, use-capped, issuable only by the
  patient, with write scopes clamped away.

**Audit and change tracking**
- Append-only hash-chained, Ed25519-signed audit ledger with periodic anchors
  and full chain verification.
- Bitemporal record revisions with redacted diffs, state hashes and a link to
  the ledger sequence number.
- Every ledger entry and anchor carries the `software_version` that wrote it and
  the `payload_version` of its signed layout.

**Clinical**
- Dossier and document management with confidentiality-level filtering applied
  in the query, supersession and retraction instead of deletion, and a 20-year
  retention horizon that moves with the last entry.
- Medication record covering prescription, dispense, administration and
  self-reported entries against a GTIN/Swissmedic/ATC catalogue, with a
  reconciled current medication list.

**Authentication**
- SwissID OIDC relying party: authorisation code flow with PKCE, server-side
  state and nonce, single-use flows, and full ID token verification against the
  provider JWKS.
- Mandatory emailed one-time second factor with keyed hashing, constant-time
  comparison, capped attempts and single use. A `PENDING_MFA` session carries no
  authority.
- Single-use refresh tokens with reuse detection that destroys the session.
- In-process mock identity provider for development, which refuses to be
  constructed in production.

**Operations**
- Configuration that refuses to start in production without a root key, with
  the mock IdP enabled, without SwissID credentials, over plaintext HTTP or on
  SQLite.
- Single root secret with HKDF-derived, versioned subkeys per purpose.
- Security headers, request correlation ids, and an admin-key-gated `/version`
  endpoint reporting build provenance.
- `make seed` demo walking the full journey and verifying the ledger.

### Security
- Denial paths commit their audit entry and attempt counters before raising, so
  a rejected login or token cannot be erased by the request rollback.
- Field-level AEAD is bound to the entity UID and column name, so a ciphertext
  cannot be transplanted onto another patient's row.

### Licence
- Released under AGPL-3.0-or-later. See [`docs/licensing.md`](docs/licensing.md)
  for the reasoning; the repository previously carried GPL-3.0.

[Unreleased]: https://github.com/lucadesimoni/swiss-ehealth/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.4.0
[0.3.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.3.0
[0.2.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.2.0
[0.1.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.1.0
