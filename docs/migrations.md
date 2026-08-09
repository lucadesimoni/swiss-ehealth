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

## What is still missing

- **No migration has been run against PostgreSQL here.** The migration was
  generated and applied on SQLite. `render_as_batch` is enabled only for
  SQLite, and the JSONB variant is exercised by the type definition but not by
  an actual PostgreSQL run. Verify against PostgreSQL before a production
  deployment.
- **No zero-downtime tooling.** No advisory-lock guard against two migrators
  starting at once, no statement timeout, no online index creation
  (`CREATE INDEX CONCURRENTLY`). On a table of a national record's size, an
  index build without it takes a write lock for the duration.
