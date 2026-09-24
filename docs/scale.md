# Running this for the whole of Switzerland

Roughly 9 million people, ~300 000 healthcare professionals, and a record that
has to be kept for twenty years. This document is what that changes, and what
it does not.

## The bottleneck that mattered

The obvious audit ledger is one hash chain: each entry links to the previous
one, and tampering breaks every following link. It is also the wrong shape for
a country, because every append has to read and lock the same tail row. Not
"slow" — *serialised*. One writer at a time, nationally, and every clinical
action produces several audit entries.

So the chain is partitioned:

```
dossier dos_A   entry 1 ─ entry 2 ─ entry 3        one chain per patient
dossier dos_B   entry 1 ─ entry 2                  never contends with dos_A
global          entry 1 ─ entry 2 ─ entry 3 ─ …    registry, auth, catalogue
                          │
                          ▼
anchor 2026-08-07   Merkle root over every chain that moved
       │                    ▲
       ▼                    │  one value to publish
anchor 2026-08-08 ──────────┘  anchors chain to their predecessor
```

Two clinicians treating two different patients never touch the same lock.
Two writes to the *same* patient still serialise, which is the ordering a
clinician can actually reason about and the one worth paying for.

The cost of partitioning is that "verify the ledger" is no longer one walk. So:

- `GET /v1/audit/verify?chain_id=dos_…` verifies one patient's chain. This is
  the question a patient actually has, and it is O(their record) forever.
- `GET /v1/audit/verify-all` walks everything — a background job at national
  volume, not a request.
- **Anchoring** gives back the single publishable value: a Merkle root over
  every chain that moved in the period, with a checkpoint row per *active*
  chain. Cost tracks activity, not population, which is the difference between
  affordable and not.

The `global` chain is the one place that still serialises. It carries logins,
registry changes and catalogue updates — high volume but not clinical, and it
can be split further by category the same way if it becomes the limit.

## What each number does to the design

| Quantity | Order of magnitude | Consequence |
|---|---|---|
| People | 9 × 10⁶ | the 18-digit EPR-SPID has 14 significant digits, so allocation collisions are a formality; a 13-digit one would have collided constantly |
| Dossiers | ~10⁷ | ledger chains are per dossier — that is 10⁷ short chains, which is fine, and one chain of 10⁹ entries, which is not |
| Professionals | ~3 × 10⁵ | credential and licence checks are per request, so they are indexed lookups, not scans |
| Audit entries | 10⁹+ over 20 years | partitioned by dossier and time-ordered within it; a patient's trail is a range scan on `(chain_id, seq)` |
| Retention | 20 years | `retention_until` moves with the last entry; archival is a policy job, not a delete |

## Multilingualism

Four national languages plus English, and this is not decoration — a patient
who cannot read their own record has not been given access to it.

Implemented: documents carry a `language` (`de-CH` default), the second-factor
email goes out in German, French and English.

Not implemented: the API's `title`/`detail` strings in problem responses are
English only. The `type` URI is what clients branch on, so a localised
presentation layer is possible today, but the service does not negotiate
`Accept-Language`. Romansh is in no path yet. Both are honest gaps rather than
oversights — they need translation work, not code.

## Federation

An EPD for the whole country is not one deployment; it is certified
communities (Gemeinschaften) that federate. `Organization.community` records
the affiliation and `Dossier.home_community` the patient's, but the IHE
transactions that make federation real — XDS.b for documents, PIX/PDQ for
patient identity, CH:ATC for access control — are **not implemented**. The
internal model is shaped to map onto them: document class, confidentiality
codes, the EPR-SPID as the patient identifier, GLN as the professional's.

The EPR-SPID is also where a real deployment stops deriving and starts asking:
the ZAS UPI service allocates it. `IdentityService.spid_candidates` is the
seam, and the allocation loop plus the uniqueness constraint stay either way.

## Operational shape

- **Stateless application.** All state is in Postgres; scale horizontally.
- **Read replicas** serve `/audit/me`, document lists and catalogue search.
  Writes need the primary because of the chain locks.
- **Partition `audit_event` by time** in Postgres once it is large; the
  `(chain_id, seq)` index carries the per-patient queries either way.
- **The catalogue is not patient data** and can be cached aggressively.
- **Anchoring** is a scheduled job. Publish the anchor hash somewhere the
  operator cannot rewrite; without that, the ledger's guarantee is only as
  strong as key custody.

## What has not been proven

Stated plainly, because "designed to scale" and "known to scale" are different
claims and only one of them is true here:

- **The first load test found a real concurrency bug, now fixed.**
  `make load-test` runs the real app with uvicorn against PostgreSQL 16 and
  drives it over HTTP: ITI-65 publish, ITI-67 find, ITI-68 retrieve, and PDQm
  search, from concurrent workers. The first run (30 patients, 8 workers, 30
  s) lost **2.7 % of requests** with a 500. Two appends to the same dossier's
  chain claimed the same sequence number, because the tail was locked with
  `SELECT … FOR UPDATE`. A waiter re-reads the *old* tail row once the lock
  is released, and an empty chain has no row to lock. The unique constraint
  kept the chain intact, so nothing was corrupted, but requests failed. A
  per-chain transaction advisory lock replaced it. After the fix, the same run
  gave **0 errors** and every chain verified:

  | operation | req/s | p50 ms | p95 ms | p99 ms |
  |---|---|---|---|---|
  | publish (ITI-65) | 9.8 | 218 | 308 | 367 |
  | find (ITI-67) | 12.8 | 182 | 254 | 293 |
  | retrieve (ITI-68) | 16.6 | 168 | 238 | 269 |
  | search (PDQm) | 3.8 | 136 | 205 | 262 |

  Single process, one laptop-class container, eight workers concentrated on
  only 30 dossiers. That concentration is deliberately worse than reality,
  where two clinicians rarely write to one patient at the same instant. Read
  these numbers as a floor for comparing versions, not as a capacity figure.
  Latency rose after the fix because requests to one dossier now queue instead
  of failing. **Reads write too**: every document read appends an audit entry
  to that dossier's chain, so concurrent reads of one patient serialise. That
  is the price of an audit trail patients can check. If a hot dossier ever
  matters, the lever is to batch ledger appends, not to drop them.
- **Not yet measured:** many workers across many dossiers (where the
  partitioning should shine), multiple app processes, and a separate database
  host.
- **The restore is rehearsed** (`make restore-rehearsal`): on the load-test
  data, 3,920 rows and 2,803 audit entries round-tripped through
  `pg_dump`/`pg_restore`, and every chain re-verified. With a different root
  key, every chain fails. **Back up the key alongside the data, or the backup
  cannot be verified.**
- **`verify_all` is O(everything).** Fine as a nightly job on a replica;
  it is not an endpoint to call in production against the primary.
- **Anchor checkpoint growth** is proportional to daily active dossiers. At
  national scale that is a large table over twenty years and will need its own
  retention policy — anchors are cheap to keep, per-chain checkpoints less so.
