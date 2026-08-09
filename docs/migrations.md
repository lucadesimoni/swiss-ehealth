# Database migrations

A health record is kept for twenty years. The schema will change many times
over that span, always with live data in it, and every one of those changes is
a chance to lose a column somebody's medication list depended on. This is how
that is kept boring.

## Two version numbers, and why

| | What it is | Who reads it |
|---|---|---|
| `alembic_version` | the revision hash, e.g. `dbc126357ff5` | alembic |
| `schema_metadata.schema_version` | the number in the changelog, e.g. `3` | people, `GET /v1/version`, the boot guard |

The hash tells you exactly which migration ran; the number tells you which
compatibility row in [`CHANGELOG.md`](../CHANGELOG.md) applies. Both are
written by the same migration, in the same transaction, so a database can never
claim a version it does not have.

## The boot guard

The application refuses to start against a schema it does not expect, in
**both** directions:

- **Database older than the code** — migrations were not run. Refuses, and
  names the command.
- **Database newer than the code** — a rollback that skipped its migration.
  Refuses, because the old build does not know about columns the new schema
  requires and writing through it can silently drop data. That direction is
  the dangerous one and the one people forget.

Both are one-line fixes at boot and expensive to find in the data weeks later.

## Making a change

```bash
# 1. change the models
# 2. generate the migration
make migration name="add allergy table"

# 3. read what it produced   <- not optional
# 4. bump SCHEMA_VERSION in src/ehealth/version.py
# 5. call stamp_schema_version() at the end of its upgrade()
# 6. add the compatibility row to CHANGELOG.md
make test
make migrate
```

**Autogenerate is a first draft, not an answer.** It cannot see:

- **Renames.** It emits a drop plus an add, which is data loss that passes
  every test. Write `op.alter_column(..., new_column_name=...)` by hand.
- **Data migrations.** Backfilling a new non-null column, or re-encoding a
  field under a new key version, is code you write.
- **Anything outside the table definitions** — triggers, partitions, grants.
- **Order.** On a large table, adding a non-null column with a default rewrites
  it. Add nullable, backfill in batches, then add the constraint.

## The test that matters

`tests/test_migrations.py::TestNoDrift::test_migrations_match_the_models` runs
the migrations on an empty database and asks alembic whether the result differs
from the models.

Without it, drift is silent: the test suite builds its schema with
`create_all`, so a model change with no migration passes everything and only
breaks in production, where `create_all` never runs. That failure mode is why
this test exists, and it has been checked against real drift — adding an
undeclared column to a model makes it fail.

## Rules

- **Migrations are append-only once released.** Editing one that has run
  somewhere means two databases with the same revision hash and different
  shapes. Fix forward with a new migration.
- **One head.** Two people migrating in parallel produce two heads and the next
  `upgrade head` fails for everyone; the test suite catches it.
- **The initial migration does not downgrade.** Dropping every table is not a
  rollback, it is data loss with extra steps — restore a backup instead. Later
  migrations should have real downgrades where a real downgrade exists.
- **Test the downgrade** if you write one. An untested downgrade is worse than
  none, because it will be trusted in an incident.

## In production

```bash
alembic upgrade head          # run before the new build starts
```

Order matters: migrate first, then deploy. The guard enforces the consequence
either way, but a deploy that starts before its migration simply refuses to
serve rather than half-working.

For a rolling deploy where old and new run simultaneously, the usual
expand/contract applies: additive migration → deploy → backfill → a second
migration that removes what is no longer read. Every intermediate state has to
be one both builds can serve, which the schema version number cannot express —
so a rolling deploy across a schema change needs the two versions to be
deliberately compatible, or a short maintenance window.

**Back up before migrating.** Test the restore, not just the backup.

## Running two migrations at once

`alembic upgrade head` takes a PostgreSQL advisory lock before it touches
anything, and a second migrator is **refused immediately** rather than left to
block:

```
another migration is already running against this database (advisory lock
held). Wait for it to finish rather than forcing this one through: two
concurrent migrations can leave the schema in a state neither of them
describes.
```

Two deployers migrating at the same time is not hypothetical — a retried
pipeline or a two-region rolling deploy does it by default. `pg_try_advisory_lock`
returns instead of blocking, so the collision is reported rather than
appearing as a deploy that hangs.

Two timeouts are set for the migration session:

| Variable | Default | Why |
|---|---|---|
| `EHEALTH_MIGRATION_LOCK_TIMEOUT` | `5s` | An `ALTER TABLE` waits behind any open transaction on the table, and every *later* query queues behind the waiting `ALTER` because PostgreSQL grants locks in order. One long-running report can therefore stall the whole table. Giving up after five seconds turns an outage into a retryable deploy. |
| `EHEALTH_MIGRATION_STATEMENT_TIMEOUT` | `0` (none) | A legitimate index build on a national-scale table runs for hours and must not be killed halfway. Set it for migrations you expect to be quick. |

On SQLite the guard is a no-op: there is only ever one writer.

## PostgreSQL

The migrations are run against PostgreSQL 16 by
`make test-postgres PGURL=…` and by the `test-postgres` job in CI, which also
runs `alembic upgrade head` as a bare command — the way an operator does —
and then runs it a second time to prove a redeploy is a no-op.

The drift check runs on whichever backend the suite is pointed at, so on
PostgreSQL it compares against real reflected types. It reports zero
differences, which is the evidence that the JSONB variant and the custom
`UtcDateTime` reflect back as what they were declared to be.

## What is still missing

- **No online index creation.** `CREATE INDEX CONCURRENTLY` cannot run inside
  a transaction, so it needs a migration marked as non-transactional and a
  different failure story (a failed concurrent build leaves an invalid index
  that must be dropped by hand). On a table of a national record's size, an
  ordinary index build takes a write lock for its whole duration.
- **No expand/contract tooling.** The procedure below is written down but
  nothing enforces that a migration is safe to run against the previous
  build's code.
- **No restore rehearsal.** Backups are named in the deployment guide; nothing
  here tests that one can actually be restored.
