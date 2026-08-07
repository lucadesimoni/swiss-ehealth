# Security

## What "secure" means here, and what it does not

Nothing is absolutely secure, and a health record that claims to be is asking
you to stop checking. What this system does is make specific attacks fail in
specific ways, and make the ones it cannot prevent *detectable*. This document
says which is which, so you can decide whether that is enough for your
deployment.

Report a vulnerability privately via GitHub Security Advisories on this
repository. Please do not open a public issue for anything exploitable.

## Threat model

| Adversary | What they get | What stops them |
|---|---|---|
| Someone who steals a capability token | one dossier, one purpose, minutes | short TTL, `jti` registry, consent re-checked at every use, optional holder-key binding |
| Someone who steals a session token | the person's own view, 15 minutes | AAL2 required, single-use refresh with reuse detection that kills the session |
| Someone who dumps the database | pseudonyms and ciphertext | AHVN13 never stored; names, contacts and card numbers AEAD-sealed to their row; keys are not in the database |
| An operator quietly editing records | nothing quiet | hash-chained signed ledger; any edit or deletion breaks every following link |
| An operator rewriting history wholesale | everything since the last anchor | published anchors freeze everything before them |
| A struck-off professional with a live token | nothing | role and licence re-checked on every authorisation |
| A cloud provider reading disks | ciphertext, if the KMS is not theirs | field-level AEAD under a root key held in an HSM/KMS you control |
| Someone with the signing key | forged tokens and ledger entries | **not prevented** — see below |
| Someone with the root key | everything | **not prevented** — see below |

### What is explicitly *not* covered

- **Root key compromise is total.** Every pseudonym, ciphertext, token and
  ledger signature derives from it. It belongs in an HSM or a KMS you control,
  never in an environment variable on a shared host, and its rotation is an
  operational procedure this code cannot perform for you.
- **A live signing key can forge ledger entries.** The chain proves nobody
  edited history *without* the key. Anchors published outside the operator's
  control are what bound the damage; without them, the ledger's guarantee is
  only as strong as key custody.
- **Email as second factor inherits the security of the mailbox.** It is the
  pragmatic choice for population-scale rollout, not a strong factor. The
  session's assurance level and `OtpChallenge.channel` are the seams where
  FIDO2 or SwissID step-up drop in.
- **Availability.** There is no rate limiting on most endpoints, no WAF and no
  DDoS protection in this codebase; those belong at the ingress.
- **The client.** Anything running on a compromised clinician workstation can
  do whatever that clinician can.
- **Compromise of the identity provider.** A malicious SwissID could
  authenticate anyone; the second factor is what keeps that from being enough
  on its own.

## Properties the code enforces

Each of these has a test that fails if it stops being true.

**Identity**
- The AHVN13 exists in no queryable column, no log line and no API response.
  A test dumps the `person` table and asserts the digits appear nowhere.
- `Ahvn13.__repr__` is masked, so an accidental f-string cannot leak one.
- Re-identification needs a stated legal basis and audits *before* decrypting.

**Cryptography**
- One root secret; every subkey HKDF-derived with a purpose label and version,
  so key separation is structural.
- Field AEAD binds the entity UID and column name, so a ciphertext cannot be
  transplanted onto another patient's row.
- Closed signature-algorithm registry. `none` does not exist; an algorithm that
  is registered but unimplemented fails closed rather than falling back.
- A signature made with the audit key cannot authorise access, and vice versa.

**Authorisation**
- Every bearer token is registered and revocable.
- Consent, role and licence are re-evaluated at *use* time, not issue time.
- Confidentiality filtering happens in the query; material above the caller's
  ceiling is never loaded, counted or hinted at, and reads as "not found".
- Denials are audited and committed before the request rolls back.

**Operations**
- Production refuses to start without a root key, with the mock IdP enabled,
  without SwissID credentials, over plaintext HTTP, or on SQLite.
- The container runs as UID 10001, with a read-only root filesystem, all
  capabilities dropped and no new privileges.
- Failure responses are uniform: a probe cannot distinguish "no such account"
  from "wrong code" from "locked".

## Deployment checklist

Before this touches real patient data:

- [ ] Root key generated in an HSM/KMS, never on disk, with a documented
      rotation and custody procedure
- [ ] `EHEALTH_ENVIRONMENT=production` (which enforces most of the rest)
- [ ] TLS terminated with a current configuration; HSTS is already sent
- [ ] `EHEALTH_ADMIN_API_KEY` set to a high-entropy value, or the enrolment
      endpoints left disabled
- [ ] Real SwissID credentials; mock provider off (production refuses otherwise)
- [ ] Database encrypted at rest, backups encrypted and restore-tested
- [ ] Ledger anchors published somewhere the operator cannot rewrite
- [ ] Rate limiting and request-size limits at the ingress
- [ ] Log pipeline that does not ship request bodies
- [ ] Dependency scanning in CI (`pip-audit`) and a patch SLA
- [ ] Penetration test by a third party
- [ ] EPDG certification process started with a recognised certification body
      — the code can support it, it cannot satisfy it

## Supported versions

Pre-1.0: only the latest release receives security fixes. See
[`docs/versioning.md`](docs/versioning.md).
