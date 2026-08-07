# Swiss e-health patient dossier

An electronic patient record built around four commitments:

1. **Every person has one UID, derived from their AHV number — and the AHV
   number is never stored.**
2. **Nothing is read or written without a scoped, expiring, revocable token.**
3. **Every access and every change is recorded in a tamper-evident ledger.**
4. **The patient decides who sees what, and can revoke it instantly.**

Login is SwissID (OIDC, authorisation code + PKCE) with a mandatory emailed
one-time code as second factor. Health data is pseudonymised at rest, direct
identifiers are encrypted field-by-field, and the whole configuration refuses
to start in production if any protection is switched off.

---

## The identity chain

The single most important design decision in this codebase is what happens to
the AHV number.

```
   756.1234.5678.97          the AHVN13, supplied once at registration
          │
          │  HMAC-SHA256 under the sector key (HSM/KMS in production)
          ├──────────────────► ppid    p1_x7Kf…  256-bit linkage key, the join
          │                              key for all health data
          ├──────────────────► spid    761.4820.9173.6   13-digit sector id,
          │                              allocated, for interop and display
          ├──────────────────► index   v1:9Fh2…  rotatable blind index
          │
          └──────────────────► sealed  AES-256-GCM envelope, bound to the ppid
                                        (omitted entirely in zero-retention mode)

   the AHVN13 itself is discarded — it exists in no queryable column
```

Why not simply key on the AHVN13? Because Swiss law deliberately does not:
EPDG/LEPD art. 5 has the central compensation office derive a separate sector
identifier (EPR-SPID) precisely so that a leak of health data cannot be joined
against the pension, tax and employer systems that also key on the AHVN13, and
AHVG art. 50g constrains who may use it systematically at all. This
implementation reproduces that separation locally.

Two identifiers come out, for two different jobs:

- **`ppid`** — 256 bits, collision-free, never displayed. This is what health
  data actually hangs off.
- **`spid`** — 13 digits in EPR-SPID shape (`761.xxxx.xxxx.xx`). Nine
  significant digits *cannot* be collision-free for a population of millions,
  which is exactly why the real EPR-SPID is allocated by a registry rather than
  derived. So this one is allocated too: derivation proposes a candidate, a
  uniqueness constraint disposes, and `IdentityService.spid_candidates` yields
  the next candidate on collision.

Re-identification is possible only where the deployment chose to keep the
sealed copy, requires a stated legal basis, and writes its audit entry *before*
decrypting — so an aborted disclosure still leaves a trace.

Every other entity gets a type-prefixed, time-sortable UID from the same
scheme: `pat_`, `hcp_`, `vis_`, `dos_`, `doc_`, `med_`, `mst_`, `grt_`, `cns_`.
Passing a visitor UID where a patient UID belongs is a parse error, not a
subtle bug.

## Tokens

A token here is not "who you are" — it is a **capability**: one dossier, one
purpose, one confidentiality ceiling, an explicit scope list, and minutes of
life. A stolen token buys an attacker one narrow thing briefly, not everything
its holder could ever do.

```
Authorization: Bearer <session token>     ← who is calling (SwissID + OTP, AAL2)
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
rather than merely discouraged. Periodic **anchors** seal the head; publish one
outside the operator's control and everything before it is frozen, because a
rewrite would have to produce a different head hash than the one already out
there.

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

Full policy and release procedure in [`docs/versioning.md`](docs/versioning.md);
history in [`CHANGELOG.md`](CHANGELOG.md).

## Running it

```bash
make install     # virtualenv + dependencies
make test        # 276 tests
make seed        # a demo dataset with a full patient journey
make run         # http://localhost:8000/docs

make version         # release identity of this checkout
make verify-version  # version numbers agree across the three files
make release VERSION=0.2.0
```

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

- **Document storage.** `DossierDocument` records the SHA-256 and a storage
  reference; the blob itself belongs in object storage. The hash is what makes
  that storage untrusted-by-default.
- **Schema migrations.** `create_all` covers development. Production needs
  Alembic; the constraint naming convention in `db.py` is already set up for it.
- **The IHE/XDS profiles** (XDS.b, PIX/PDQ, CH:ATC) that a real EPD community
  must speak to federate with other communities. The internal model is shaped
  to map onto them — document class, confidentiality codes, home community —
  but the transactions are not implemented.
- **Post-quantum signatures.** ML-DSA-65 is registered in
  `SIGNATURE_ALGORITHMS` and marked unavailable; a token claiming it fails
  closed. The crypto-agile envelope is what makes adding it a local change
  rather than a migration.
- **Notification delivery** for emergency access and `notify_on_access`. The
  decision carries the flag; the transport is not written.

## Standards this follows

EPDG/LEPD and EPDV (participation, access levels, the audit trail patients can
read, 20-year retention), the revised DSG (privacy by design and by default,
right of access), AHVG art. 50g (constraints on systematic use of the AHVN13),
OIDC Core + RFC 7636 (PKCE), RFC 8725 (JWT best practices), NIST SP 800-63B
(AAL2 for interactive sessions).

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
