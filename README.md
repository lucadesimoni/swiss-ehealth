# Swiss e-health patient dossier

An electronic patient record built around four commitments:

1. **Every person has one UID, derived from their AHV number — and the AHV
   number is never stored.**
2. **Nothing is read or written without a scoped, expiring, revocable token.**
3. **Every access and every change is recorded in a tamper-evident ledger.**
4. **The patient decides who sees what, and can revoke it instantly.**

Login is SwissID, HIN or another OpenID Connect provider (authorisation code
+ PKCE), with a required level of assurance per provider. The provider's own
two factors, or else an emailed one-time code, are the second factor. Health data is pseudonymised at rest, direct
identifiers are encrypted field-by-field, and the whole configuration refuses
to start in production if any protection is switched off.

---

## The identity chain

The single most important design decision in this codebase is what happens to
the AHV number.

```
   756.1234.5678.97           the AHVN13 — 13 digits, supplied once
          │
          │  HMAC-SHA256 under the sector key (HSM/KMS in production)
          ├──────────────────► ppid    p1_x7Kf…  256-bit linkage key, the join
          │                              key for all health data
          ├──────────────────► spid    761252402452346988   the EPR-SPID,
          │                              18 digits, allocated, for interop
          ├──────────────────► index   v1:9Fh2…  rotatable blind index
          │
          └──────────────────► sealed  AES-256-GCM envelope, bound to the ppid
                                        (omitted entirely in zero-retention mode)

   the AHVN13 itself is discarded — it exists in no queryable column
```

**Two lengths, two identifiers, and confusing them is the classic Swiss
integration bug.** The AHV number is **13 digits** (`756.XXXX.XXXX.XX`, EAN-13
check digit). The **EPR-SPID is 18 digits** (`761…`) — derived from the AHVN13
but a different identifier for a different purpose. Both are validated
strictly and separately, and a 13-digit value is rejected as an EPR-SPID.

Why not simply key on the AHVN13? Because Swiss law deliberately does not:
EPDG/LEPD art. 5 has the central compensation office derive a separate sector
identifier precisely so that a leak of health data cannot be joined against the
pension, tax and employer systems that also key on the AHVN13, and AHVG
art. 50g constrains who may use it systematically at all. This implementation
reproduces that separation locally.

Two identifiers come out, for two different jobs:

- **`ppid`** — 256 bits, collision-free, never displayed. This is what health
  data actually hangs off.
- **`spid`** — 18 digits, prefix 761, with fourteen significant digits. Still
  *allocated* rather than merely derived — derivation proposes a candidate, a
  uniqueness constraint disposes — because two patients sharing an identifier
  is not a failure mode worth risking, however unlikely.

In a certified EPDG deployment the EPR-SPID is **allocated by the ZAS UPI
service**, not computed locally. Deriving it here gives a correctly shaped,
stable identifier for a deployment not connected to the UPI; the allocation
loop and the uniqueness constraint stay either way, so swapping in a real UPI
client changes one method and nothing else.

Re-identification is possible only where the deployment chose to keep the
sealed copy, requires a stated legal basis, and writes its audit entry *before*
decrypting — so an aborted disclosure still leaves a trace.

Every entity gets a type-prefixed, time-sortable UID: `per_`, `org_`, `dos_`,
`doc_`, `med_`, `mst_`, `grt_`, `cns_`, `crd_`. Note there is one prefix for
*all* natural persons — see below.

## One person, several roles

A physician is also somebody's patient. A nurse visits their own parent in
hospital. A paediatrician is the legal representative of their child.

Making the role a property of the person forces those people into two records
with two pseudonyms, and a patient whose own doctor cannot see their record
because the system split them in half is not an edge case, it is Tuesday. So
roles are rows:

```
per_01KZE…  Beat Arzt
   ├─ role: patient                       active since 2026-08-07
   └─ role: healthcare_professional       active since 2026-08-07
        └─ credential crd_01KZE…
             GLN 7601000000002 · MedReg · Facharzt Allgemeine Innere Medizin
             licence ZH-2019-04412 (ZH), live · ZSR A123456
             verified against MedReg on 2026-08-07
```

Authority is therefore always a question asked of the database at the moment it
matters, never something baked into an identifier. A doctor struck off
yesterday does not get in today, whatever token they hold — the role and the
licence are re-checked on every authorisation.

## Identifying professionals and medicines the way Swiss law does

**Professionals** — three things have to line up, and they are separate because
they fail separately:

| | What it establishes | Source |
|---|---|---|
| **GLN** | the identifier the EPD, e-prescriptions and e-invoicing key on | Refdata |
| **Federal register** | that the profession is recognised at all | MedReg (MedBG art. 51 ff.), NAREG (GesBG), PsyReg (PsyG) |
| **Cantonal licence** | that they may actually practise — this is what expires and gets suspended | the canton |

The **ZSR/RCC** billing number is recorded alongside but is deliberately *not*
part of the authority test: it says who may invoice an insurer, not who may
treat a patient. Verification against a register is recorded with its source
and timestamp, because "we were told" and "we checked" must never look the same
in a health record.

**Medicines** — four identifiers, because Swiss practice uses four and they
answer different questions: the **Swissmedic authorisation number** (is it
legally on the market, HMG art. 9), the **GTIN** (which package, scanned off
the box), the **Pharmacode** (Refdata's article number, what logistics speaks),
and the **ATC** (which substance class, for interaction checks across brands).
What actually gates prescribing is the **Abgabekategorie** (A/B/D/E — category C
is absent, having been abolished in 2019) and the **BetmVV-EDI narcotic
schedule**.

Prescribing is enforced at the write: a category A or B product needs an active
professional role *and* a live cantonal licence for a profession that may
prescribe. Patients can still record their own self-medication — a complete
medication list is worth more than a tidy one. Every statement stores the
credential and GLN it was made under, copied rather than joined, so it stays
attributable to the licence that was live at the time.

## Tokens

A token here is not "who you are" — it is a **capability**: one dossier, one
purpose, one confidentiality ceiling, an explicit scope list, and minutes of
life. A stolen token buys an attacker one narrow thing briefly, not everything
its holder could ever do.

```
Authorization: Bearer <session token>     ← who is calling (provider + 2nd factor, AAL2)
X-Capability:  <capability token>         ← what they may do, to which dossier
X-Holder-Key:  <public key>               ← optional proof-of-possession
```

Deviations from stock JWT, all deliberate:

| Stock JWT | Here | Why |
|---|---|---|
| `alg` read from the token | validated against a closed registry; `none` does not exist | algorithm confusion has no surface |
| key id opaque | `token-signing.v2` — purpose **and** version | rotation needs no flag day; an audit-key signature cannot authorise access |
| stateless, unrevocable | every `jti` registered in the database | a bearer token you cannot revoke has no place in a health record |
| authorisation frozen at issue | consent re-evaluated **at every use** | a patient who revokes now is protected from a token minted a minute ago |
| — | `dlg` delegation chain | a visitor's token still says who ultimately authorised it |

Refresh tokens are single-use. Presenting a spent one is the signature of a
stolen token being replayed, so the whole session dies rather than the request
merely failing.

## Consent, in one paragraph

Participation is voluntary and revocable. Within it the patient sets a default
access level and may add per-professional or per-institution rules; a DENY rule
always beats an ALLOW, whatever its specificity, because an exclusion the
patient made explicitly must never be undone by a broader permission. Documents
marked SECRET are reachable by the patient alone — a rule that tries to hand
SECRET to someone else is clamped, not honoured, which is what makes the level
worth trusting. Emergency access exists, is capped below SECRET, requires the
patient not to have disabled it, and always flags the patient for notification:
break-glass that leaves no trace is a backdoor, not break-glass.

The whole policy is a pure function — `evaluate_policy` in
`services/access.py` — so it is testable without a database and reviewable by
someone who does not read SQLAlchemy. `tests/test_access_policy.py` is the
policy written out as 24 cases.

## Change tracking

Two structures that cross-verify each other:

**The ledger** (`audit_event`) is append-only and hash-chained:
`entry_hash = H(prev_hash ‖ payload_hash)`, each entry signed with Ed25519.
Editing or deleting any row breaks every subsequent link, so tampering by
anyone with database write access — including the operator — is detectable
rather than merely discouraged.

It is **one chain per dossier**, not one chain overall. A single global chain
is the obvious design and it cannot serve a country: every append locks the
same tail row, so the whole nation's writes serialise. Per-dossier chains mean
two clinicians treating two different patients never contend, while writes to
the same patient still order correctly — the ordering that actually matters
clinically.

Periodic **anchors** give back the single value to publish: a Merkle root over
every chain that moved in the period, linked to the previous anchor. Put one
somewhere the operator cannot rewrite and everything before it is frozen.

```
GET /v1/audit/verify?chain_id=dos_…   one patient's chain — cheap, forever
GET /v1/audit/verify-all              everything — a background job at scale
POST /v1/audit/anchor                 seal the period, publish the hash
```

**The revision history** (`record_revision`) is bitemporal: every row's every
version, with the diff, who made it, why, and a hash of the resulting state.
Each revision points at the ledger sequence number that recorded it. Replaying
revisions in order reconstructs any row as it stood at any past instant.

Protected fields never appear in a diff as plaintext — they are reduced to a
hash. A change history that faithfully recorded "family_name changed from X to
Y" would quietly become a second, unprotected copy of the record.

Clinical data is never deleted: documents are superseded or retracted,
medication is stopped or marked `entered_in_error`. A later reader has to be
able to see that a wrong result existed and was withdrawn.

## Offline, for patients

An electronic record a patient can only reach with four bars of signal is not
their record. Two cases, one mechanism:

**The ambulance problem.** Someone collapses in a village at 02:00 with no
coverage. The paramedic needs current medication *now*, and needs to know it is
genuine and not two years stale. That is the **emergency dataset** — signed,
under 2 KB, fits a QR code on a card.

**The mobile problem.** A patient wants their record in a train tunnel and
wants to add to it there. That is the **full bundle**, plus idempotent sync
back.

```bash
GET  /v1/offline/public-key            unauthenticated — cache it once
POST /v1/offline/emergency-dataset     signed, QR-sized
POST /v1/offline/bundle                the patient's own copy
POST /v1/offline/sync                  upload offline captures, idempotent
```

What makes this genuinely offline rather than merely downloadable is that
**verification needs nothing but the public key** — no network, no account, no
trust in whoever handed the file over. `verify_bundle()` is deliberately a free
function with no database and no framework, so it can be reimplemented in
Swift, Kotlin or TypeScript by reading it.

Three properties that are easy to get wrong and are tested here:

- A bundle carries only what the presenting capability reaches. The emergency
  dataset is `NORMAL` only — a bundle leaving the system loses every access
  control the system has, so what the patient *hid* must never travel on a card
  they carry.
- An expired bundle still **verifies**. It is still authentic; readers are told
  it is stale. Hiding staleness from a paramedic would be worse than showing
  old data labelled as old.
- Sync is idempotent per client-generated id, so a phone that loses signal
  mid-upload retries without duplicating, and reports **per item** — one bad
  row never blocks a patient's whole history. The device clock is recorded
  because it is clinically meaningful and never trusted for ordering.

Prescriptions cannot be captured offline: that needs a licensed professional
and a live licence check, neither of which happens on a phone in a tunnel.

## API-first

Everything is under `/v1`. There is no second, private interface — the app a
patient uses and the integration a hospital runs are the same API, which is the
only way an API stays honest.

Errors are **RFC 9457 problem details** with a machine-readable `type`, so
partners branch on a URI instead of parsing prose. Request bodies reject
unknown fields rather than ignoring them: a silently dropped field in a health
API is a silently dropped clinical instruction.

Integration guide, including what is **not** there yet (machine-to-machine
credentials, a change feed), in [`docs/api.md`](docs/api.md).

**Other EPD systems** look patients up through IHE **PIXm** (ITI-83) and
**PDQm** (ITI-78) over FHIR under `/v1/fhir`, per the CH EPR FHIR guide.
Only professionals may query, only patients are found, and the search terms
never reach the audit trail. What else the national network needs and this
system does not have yet is listed in
[`docs/interoperability.md`](docs/interoperability.md).

**Login** goes through SwissID, HIN or any other OpenID Connect provider,
each with its own required level of assurance. A provider's two factors can
stand in for the emailed code. Setup and the checklist for the providers'
real test environments are in
[`docs/identity-providers.md`](docs/identity-providers.md).

## Versioning

Five things version independently, because they change for different reasons
and break different consumers: the **software release**, the **HTTP API**, the
**database schema**, the **signed audit payload layout**, and the **key
versions**. `src/ehealth/version.py` is the source of truth for the first four;
`pyproject.toml` and `CHANGELOG.md` are checked against it by the test suite, so
a release whose numbers have drifted fails instead of shipping.

Every ledger entry and anchor carries the build that wrote it —
`0.1.0+g1a2b3c4`, inside the signature — so any record traces back to a commit
years later, and a `.dirty` suffix marks a build that is not reproducible from
any commit. The signed payload layout is versioned with a builder per version
that is never edited after release; a build meeting a payload version it does
not know reports a named failure rather than declaring the entry sound.

Which commit each release was cut from is recorded in
[`RELEASES.json`](RELEASES.json), not only in a git tag. A tag is a mutable
pointer beside the history that a protected-ref rule or a restricted network
can refuse to accept; the ledger is a file inside the tree that every clone
carries. Entries are verified against the repository — the suite reads
`version.py` at each recorded commit and requires it to declare exactly the
numbers claimed — so a mistyped or invented SHA fails rather than misleading an
auditor later. `make releases` prints it.

Full policy and release procedure in [`docs/versioning.md`](docs/versioning.md);
history in [`CHANGELOG.md`](CHANGELOG.md).

## Running it

```bash
make install     # virtualenv + dependencies
make test        # the full suite on SQLite
make lint        # ruff check + format check, the same gate CI runs
make seed        # a demo dataset with a full patient journey
make run         # http://localhost:8000/docs

make version         # release identity of this checkout
make releases        # the release ledger: version, commit, compatibility numbers
make verify-version  # the numbers agree, and every ledger entry matches its commit
make release VERSION=0.5.0
make record-release  # append the release commit to RELEASES.json

make migrate         # bring the database to the latest migration
make migration name="add allergy table"

# The same suite against the engine production actually uses:
make test-postgres PGURL=postgresql+psycopg://ehealth:pw@localhost:5432/ehealth
```

CI runs all of it on every push: lint, the suite on SQLite, the suite on
PostgreSQL 16 plus a bare `alembic upgrade head` twice over, and a Docker
build that is then started to check it runs as uid 10001 and reports the
revision the pipeline stamped into it.

Schema changes go through Alembic, and the application **refuses to start**
against a schema it does not expect — in both directions. A database newer than
the build is the dangerous one people forget: the old code does not know about
columns the new schema requires, so writing through it can drop data silently.

A drift test runs the migrations on an empty database and asks alembic whether
the result differs from the models. Without it drift is invisible, because the
test suite builds its schema with `create_all` and production never does.
See [`docs/migrations.md`](docs/migrations.md).

## Deploying on Swiss infrastructure

```bash
cp .env.example .env && make keygen   # paste into EHEALTH_ROOT_KEY
GIT_REVISION=$(git rev-parse HEAD) docker compose up --build -d
```

The container runs as UID 10001 with a read-only root filesystem, all
capabilities dropped, no compiler and no package manager — so a process that
gets code execution has very little to work with. The build revision is stamped
into the image, so `/version` and every audit entry name a traceable commit.

A Zurich datacentre is **not** the same thing as Swiss jurisdiction: a
US-parented provider stays subject to the CLOUD Act wherever the disks are.
[`docs/deployment-ch.md`](docs/deployment-ch.md) covers Swiss-operated
providers, key custody (the decision that determines whether the rest is
meaningful), data residency enforced rather than assumed, and what to monitor.

For 9 million people: [`docs/scale.md`](docs/scale.md) covers the ledger
partitioning, what each order of magnitude changes, multilingualism, federation
between EPDG communities — and what has **not** been proven (no load test has
been run, and there is still no migration path).

On "absolutely secure": [`SECURITY.md`](SECURITY.md) states the threat model
including what is **not** covered — root key compromise is total, a live
signing key can forge ledger entries, email is a weak second factor, and
availability is someone else's job. A health record that claims to be
absolutely secure is asking you to stop checking.

`make run` uses the in-process mock identity provider and an in-memory mail
sender, so the whole login path works without SwissID credentials. Both refuse
to exist in production.

### Configuration

Everything is `EHEALTH_`-prefixed environment variables; see `.env.example`.
The defaults are the *safe* values, so an operator has to opt in to anything
weaker. In production the settings object refuses to construct at all if the
root key is missing, the mock IdP is on, SwissID credentials are absent, the
issuer is plaintext HTTP, or the database is SQLite — and it reports every
problem at once rather than one per restart.

```bash
make keygen      # a fresh 256-bit root key
```

One root secret, everything else HKDF-derived from it with a purpose label and
a version. Key separation is structural rather than a matter of discipline, and
rotation is: bump the version, keep decrypting old envelopes, re-wrap lazily.

## Layout

```
src/ehealth/
  domain/uid.py         UIDs, AHVN13, CHE-UID, GTIN — no I/O, no secrets
  domain/identity.py    AHVN13 → ppid / spid / blind index / sealed copy
  security/crypto.py    key hierarchy, AEAD, signatures, algorithm registry
  security/tokens.py    capability tokens
  security/oidc.py      SwissID relying party (+ mock provider)
  security/mfa.py       emailed one-time codes
  models/               the schema, one file per bounded context
  services/audit.py     the hash-chained ledger
  services/changelog.py record versioning and diffs
  services/access.py    consent policy, grants, authorisation
  services/…            persons, dossier, medication, auth
  api/                  FastAPI routes, schemas, dependencies
  container.py          composition root — the only place keys are wired
```

## What is deliberately not built

Stated plainly so nobody mistakes a stub for a feature:

- **An S3 backend for documents.** Contents are stored encrypted on a local
  or mounted file system (`EHEALTH_DOCUMENT_STORE_PATH`). An S3-compatible
  backend on a Swiss provider needs only the three methods of `BlobBackend`.
- **The SOAP side of the IHE profiles** a real EPD community still needs
  between communities: XDS.b/XCA, XCPD, ATNA. The FHIR side is implemented:
  PIXm, PDQm with `$match`, MHD, CH:ATC and IUA access tokens. Details and
  the remaining gaps are in
  [`docs/interoperability.md`](docs/interoperability.md).
- **Post-quantum signatures.** ML-DSA-65 is registered in
  `SIGNATURE_ALGORITHMS` and marked unavailable; a token claiming it fails
  closed. The crypto-agile envelope is what makes adding it a local change
  rather than a migration.
- **Notification delivery** for emergency access and `notify_on_access`. The
  decision carries the flag; the transport is not written.

## Ownership and supply chain

The software cannot be made unhackable, and nothing here claims it is. What
it does is make each layer of defence something a test checks:

- every runtime dependency is pinned by hash;
- CI audits the dependencies for known vulnerabilities and produces a bill
  of materials (SBOM);
- the CI actions themselves are pinned to exact commits.

Swiss ownership is a legal and organisational step: a Swiss entity holding
the copyright and the name, and Swiss Git hosting as the source of truth. See
[`docs/sovereignty.md`](docs/sovereignty.md).

## Standards this follows

EPDG/LEPD and EPDV (participation, access levels, the audit trail patients can
read, 20-year retention), the revised DSG (privacy by design and by default,
right of access), AHVG art. 50g (constraints on systematic use of the AHVN13),
OIDC Core + RFC 7636 (PKCE) + RFC 7523 (`private_key_jwt`), RFC 8725 (JWT
best practices), NIST SP 800-63B (AAL2 for interactive sessions), HL7 FHIR R4
with IHE PIXm/PDQm as constrained by the CH EPR FHIR guide.

---

## Kurzfassung (DE)

Elektronisches Patientendossier mit maximaler Schweizer Datenhoheit:

- **UID für alle Personen** — Patient:innen, Fachpersonen, Besucher:innen —
  abgeleitet aus der AHV-Nummer. Die AHV-Nummer selbst wird **nirgends
  gespeichert**: aus ihr entstehen ein 256-Bit-Pseudonym, eine 13-stellige
  Sektor-ID (761.xxxx.xxxx.xx, analog EPR-SPID) und ein rotierbarer Blindindex.
- **Tokenisierter Zugriff**: jeder Zugriff braucht ein kurzlebiges,
  zweckgebundenes, jederzeit widerrufbares Capability-Token. Die Einwilligung
  wird bei *jeder Nutzung* neu geprüft, nicht bei der Ausstellung.
- **Lückenlose Änderungsverfolgung**: hash-verkettetes, signiertes Audit-Log
  plus vollständige Versionsgeschichte jedes Datensatzes. Manipulation ist
  nachweisbar, nicht bloss unwahrscheinlich.
- **Medikation** vollständig erfasst: Verordnung, Abgabe, Verabreichung und
  Selbstmedikation, GTIN-/Swissmedic-/ATC-referenziert, mit abgeglichener
  aktueller Medikationsliste.
- **Besucher:innen** erhalten eigene UID und zeitlich sowie in der Anzahl
  Zugriffe begrenzten Nur-Lese-Zugang, den nur die Patientin selbst vergibt.
- **Login mit SwissID** (OIDC + PKCE) und verpflichtender **2FA per E-Mail**.
  Ohne zweiten Faktor hat die Sitzung keinerlei Berechtigung.
- **Datenhoheit**: konfigurierte Schweizer Datenregion, ein einziges
  Wurzelgeheimnis (HSM/KMS), krypto-agile Algorithmus-Registry, keine externen
  Abhängigkeiten zur Laufzeit.

## Licence

**AGPL-3.0-or-later.** Every source file carries an SPDX identifier, and the
test suite fails if one is missing.

The system is a network service, and that decides the licence: AGPL §13 means
anyone who *operates* a modified version for others must offer them its source.
Without it, a foreign cloud provider could fork this into a closed hosted EPD
platform and return nothing — the exact dependency the sovereignty requirement
exists to prevent.

On jurisdiction: the AGPL carries **no choice-of-law and no venue clause**, so
between Swiss parties Swiss law applies and Swiss courts hear it. That is why
the EUPL was rejected despite being the obvious public-sector candidate — its
Article 15 imports the law of an EU Member State, Belgian law and CJEU
jurisdiction.

Reasoning in full, including the Swiss-law caveats on liability disclaimers
(OR Art. 100) and the contribution terms, in
[`docs/licensing.md`](docs/licensing.md).
