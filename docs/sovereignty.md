# Swiss ownership and a hardened codebase

The brief: source code that is **non-hackable** and **Swiss-owned**. This
document says what can be delivered against each, what this repository
already does, and what only an organisation can do. Where the brief can't be
met literally, it says so.

## "Non-hackable" is not a property software can have

No system connected to a network can honestly be called non-hackable, and a
supplier who claims otherwise should not be trusted with health data. What
can be achieved, and verified, is this:

1. **Fewer ways in.** Every endpoint is authenticated except login, health,
   public keys and the FHIR capability statement. Bodies are size-limited
   before any code reads them. The AHV number is never stored in a
   searchable form.
2. **Less gained by any single break-in.** Tokens are narrow and expire in
   minutes. Document contents and direct identifiers are encrypted, with keys
   per purpose, and storage is treated as untrusted. Confidentiality levels
   are enforced inside the database query.
3. **No undetected tampering.** Every access and change goes into signed,
   hash-chained audit chains, one per patient. Those chains are checked after
   concurrent load and again after a restore.
4. **Mistakes caught before they ship.** CI runs lint, the test suite on
   SQLite and PostgreSQL, a load test, a restore rehearsal, a dependency
   vulnerability audit and a Docker build on every push. The most important
   security checks are covered by tests that fail when the check is removed.
5. **Honest records.** `SECURITY.md` states what is *not* covered: compromise
   of the root key, a signing key that is still live, and the security of
   the mailbox behind the emailed code.

Independent verification is what makes this credible, and it can't come from
this repository: an **external penetration test**, an **independent code
audit**, and later the **E-GD / EPD certification audit**. For federal systems the
Confederation also runs a public bug bounty programme through the National
Cyber Security Centre (NCSC). An operator of this system can use the same
route.

## Software supply chain

The code that runs includes everything it installs. What this repository
enforces:

| Measure | Where |
|---|---|
| Every runtime dependency pinned by version **and SHA-256** | `requirements.lock`; the Docker image installs only from it with `--require-hashes` |
| The lockfile must match `pyproject.toml` | CI `supply-chain` job |
| No known vulnerability in any runtime dependency | `make audit`, and in CI on every push |
| A software bill of materials (CycloneDX) for every commit | CI artifact `sbom-<commit>` |
| CI actions pinned to commit SHAs, not moving tags | `.github/workflows/ci.yml` |
| A minimal runtime image, non-root (uid 10001), no compiler | `Dockerfile`, checked in CI |
| Every release traceable to its commit, even without tags | `RELEASES.json`, `COMPONENTS.json` |

Not yet done, and worth doing:

- **Signed commits and tags** (SSH or GPG), and **branch protection** that
  requires review and passing CI before `main` changes. These are settings in
  the Git host and in each maintainer's own setup, not code.
- **Reproducible builds.** The image is built from pinned inputs, but it has
  not been shown that two builds produce the same bytes. The base image
  should also be pinned by digest (not yet done).
- **Signed images** (for example with Sigstore) and a policy that
  deployments run only signed images.

## "Swiss-owned": what ownership of open-source code means

The code is licensed **AGPL-3.0-or-later** (see [`licensing.md`](licensing.md)).
That choice shapes what "ownership" can mean:

- **Anyone may use, study and modify it**, including outside Switzerland.
  That is what open source means. What the AGPL adds is that anyone who runs
  a modified version as a service must publish their changes. That protects
  the public investment from being privatised; it doesn't restrict who may
  use it.
- **Copyright** currently reads "swiss-ehealth contributors". For Swiss
  ownership in the legal sense, the copyright and the name should be held by
  a **Swiss legal entity**, such as an association (*Verein*), a foundation
  (*Stiftung*) or a cooperative, or by a public body such as a canton or the
  Confederation. Contributions should then come in either under a
  contributor licence agreement with that entity or under the Developer
  Certificate of Origin. The entity can later relicense, defend the licence
  in Swiss courts, and register the name as a trademark.
- **Stewardship** matters more than copyright: who decides what gets merged,
  who holds the release keys, and who answers for security. That should be
  written down in a governance document once the entity exists.

### Hosting and jurisdiction

The repository is on GitHub, a US company subject to US law, including the
CLOUD Act. For the **source code** that matters less than it seems. The code
is public by design, and a copy that is lost or altered is detected, because
every release is recorded in the ledgers and checked against its commit. For
**availability** and **control**, it does matter. The recommended setup:

1. The primary repository on **Swiss-operated Git hosting**, for example a
   self-hosted Forgejo or GitLab on Swiss infrastructure, or code.admin.ch if
   run for or by the Confederation.
2. GitHub as a **mirror** for visibility and contributions, not as the
   source of truth.
3. **CI and the build** on Swiss infrastructure too, since the build is where
   a supply-chain attack takes effect.
4. **Health data never touches any of these.** Production runs in Swiss data
   centres (`docs/deployment-ch.md`), and the configuration refuses processors
   outside the allowed Swiss domains.

## The short version

The code can't be made unhackable, but the chance of a break-in, the damage
one can do, and the time before it is noticed can all be reduced
deliberately, and each reduction can be tested. This repository does that,
and CI checks it on every push. What turns it into a credible claim is an
external audit. Swiss ownership is a legal and organisational decision: a
Swiss entity holding the copyright and the name, Swiss hosting as the source
of truth, and a written governance. The code is ready for it; the decision
isn't a code change.
