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
| 0.3.0 | v1 | 3 | 2 |
| 0.2.0 | v1 | 2 | 1 |
| 0.1.0 | v1 | 1 | 1 |

## [Unreleased]

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

[Unreleased]: https://github.com/lucadesimoni/swiss-ehealth/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.3.0
[0.2.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.2.0
[0.1.0]: https://github.com/lucadesimoni/swiss-ehealth/releases/tag/v0.1.0
