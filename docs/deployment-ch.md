# Running this on Swiss cloud infrastructure

The software is portable; what is not portable is the legal position. Under
EPDG/EPDV and the revised DSG, health data belongs on infrastructure whose
operator is subject to Swiss law and whose disclosure obligations do not run to
a foreign government. That is a procurement decision more than a technical one,
so this document covers both.

## Why not a hyperscaler's Swiss region

A Zurich datacentre is not the same thing as Swiss jurisdiction. A US-parented
provider remains subject to the CLOUD Act regardless of where the disks are,
which means the operator can be compelled to produce data without the Swiss
data subject or supervisory authority being involved. For an electronic patient
record this is the risk that matters, and no amount of encryption-at-rest
configuration on the provider's side removes it — unless *you* hold the keys,
which is exactly why the root key here is designed to live in an HSM you
control.

Encrypting fields under a key the provider never sees narrows the exposure to
metadata and ciphertext. It does not eliminate it: access patterns, timing and
the mere existence of a dossier remain visible to whoever runs the hypervisor.

## Swiss-operated options

All of these are Swiss companies operating Swiss datacentres. This is a
starting point for a procurement shortlist, not an endorsement — verify the
current certification status and contractual terms yourself.

| Provider | Shape | Notes for this workload |
|---|---|---|
| **Exoscale** | IaaS + managed Kubernetes (SKS), managed Postgres | Zurich and Geneva zones; ISO 27001; managed DBaaS removes most of the Postgres operations |
| **cloudscale.ch** | IaaS, Swiss-owned | RMA and LPG zones; deliberately minimal, so you run Postgres yourself |
| **Infomaniak** | IaaS (OpenStack), managed services | Own datacentres, own hardware, strong data-sovereignty positioning |
| **Swisscom** | Enterprise cloud, HSM-as-a-service | Relevant when you need an HSM and a Swiss enterprise contract in one place |
| **Green / Nine / Metanet** | Hosting and managed Kubernetes | Established Swiss hosters, useful for a single-tenant deployment |

For an EPD that will federate with other communities, the operator also has to
be part of a **certified community or reference community** under EPDG art. 11.
That certification covers the organisation and its processes, not this
repository.

## Key custody

This is the decision that determines whether the rest is meaningful.

```
EHEALTH_ROOT_KEY  ──HKDF──►  person pseudonym key   (never rotated in place)
                            ├─ lookup index key      (rotatable)
                            ├─ field encryption key  (rotatable)
                            ├─ token signing key     (rotatable)
                            ├─ audit ledger key      (rotatable)
                            └─ OTP binding key       (rotatable)
```

Options, in descending order of assurance:

1. **HSM** (Swisscom HSM-as-a-service, or an on-premise appliance). The root key
   is generated in the HSM and never leaves it. Requires wiring `KeyRing` to
   derive through the HSM rather than in process — a real change, and the right
   one for production.
2. **KMS with a sealed secret** injected at start-up into memory only. Workable
   today with no code change: the process reads `EHEALTH_ROOT_KEY` from a
   secrets manager at boot, and it never touches disk.
3. **Environment variable from a file.** Development only. `.env` is
   gitignored, and a checkout generates an ephemeral key so a forgotten
   configuration never silently protects real data.

Whatever you choose, write down who can access it, how rotation happens, and
what the recovery procedure is. A root key with no documented custody is an
outage waiting for its first bad afternoon.

## Deploying

### Single VM (staging, or a small community)

```bash
cp .env.example .env
make keygen                    # paste into EHEALTH_ROOT_KEY
# set POSTGRES_PASSWORD, EHEALTH_ADMIN_API_KEY, EHEALTH_ISSUER
GIT_REVISION=$(git rev-parse HEAD) docker compose up --build -d
```

Put a TLS-terminating reverse proxy in front (Caddy or nginx); the application
sends HSTS and expects to be reached over HTTPS. Bind the app to loopback — the
compose file already does — so only the proxy can reach it.

### Kubernetes

The container is built to run under a restrictive `securityContext` with no
adjustment:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
volumes:
  - name: tmp
    emptyDir: { medium: Memory, sizeLimit: 64Mi }
```

Mount `EHEALTH_ROOT_KEY` from a secret backed by your KMS, never from a
ConfigMap. Set `EHEALTH_GIT_REVISION` from the image tag so `/version` and the
audit ledger report a revision you can trace.

Pin the deployment to Swiss nodes with a `nodeSelector` on
`topology.kubernetes.io/region`, and enforce it with a scheduling policy rather
than convention — a pod that lands abroad is a data-residency incident, and it
should be impossible rather than unlikely.

### Database

PostgreSQL 15+. The schema uses `JSONB` on Postgres and plain JSON elsewhere,
so nothing changes in the code. Enable checksums (the compose file does),
encrypt the volume, and test restores rather than assuming them.

`EHEALTH_SCHEMA_VERSION` is reported at `/version`; migrations are not yet
wired up, so a production deployment needs Alembic before the first schema
change. The constraint naming convention in `db.py` is already set up for it.

## Data residency, enforced rather than assumed

- `EHEALTH_DATA_REGION` states the choice explicitly and appears in `/health`
  and `/version`, so an auditor can read it off a running instance.
- `EHEALTH_ALLOWED_PROCESSOR_DOMAINS` lists the host suffixes a processor may
  live on.
- The only outbound connections the application makes are to the configured
  SwissID issuer and the SMTP relay. There is no telemetry, no CDN and no
  managed-service call path — a network policy that denies egress by default
  needs exactly two exceptions.

## Backups

Health records are kept for twenty years (EPDV art. 10), which makes backup
strategy a legal requirement rather than an operational preference:

- Encrypted at rest, with the backup key held separately from the root key.
- Stored in Switzerland, under the same jurisdictional analysis as the primary.
- Restore-tested on a schedule, with the ledger verified after each restore —
  `GET /audit/verify` is the check that the trail survived intact.
- Ledger anchors published somewhere outside the operator's control, so a
  restore from a tampered backup is detectable rather than merely unlikely.

## Monitoring

Watch for, at minimum:

- `access.denied` and `token.rejected` rates — a spike is either a broken
  client or someone probing.
- `access.emergency` — every break-glass needs a human to look at it.
- `auth.login_failed` clustering on one account.
- `person.ahvn_unsealed` — should be rare and always explainable.
- Ledger verification failing — that is an incident, not an alert.

Ship logs to a Swiss-hosted collector, and make sure the pipeline does not
capture request bodies.
