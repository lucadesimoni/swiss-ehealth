# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The guard between the code and the database it is pointed at.

Running an application against a schema it does not expect is the quiet way to
corrupt a health record: a column the code writes but the database dropped, an
enum value the code emits that the constraint rejects halfway through a batch.
The failure surfaces hours later, in data.

So the schema states its own version, and the application refuses to start
unless it matches:

* **Database newer than code** — a rollback that skipped its migration. Refuse:
  the old code does not know about columns the new schema requires, and writing
  through it can silently drop data.
* **Database older than code** — migrations have not been run. Refuse, and say
  which command to run.

Both are one-line fixes when caught at boot and expensive when caught later.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from sqlalchemy import Engine, Integer, String, Table, inspect, select, text
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base, utcnow
from ehealth.models.base import UtcDateTime
from ehealth.version import SCHEMA_VERSION


class SchemaMismatch(RuntimeError):
    """The database is not the shape this build expects."""


class ConcurrentMigration(RuntimeError):
    """Another migration already holds the lock on this database."""


#: Advisory lock identifier for migrations. Arbitrary but fixed forever:
#: changing it would let an old and a new deployer each believe they hold the
#: only lock, which is the exact failure the lock exists to prevent.
MIGRATION_LOCK_KEY = 0x45485F4D_49475254

#: How long a migration waits for a table lock before giving up.
#:
#: This is the setting that separates a slow deploy from an outage. An
#: ``ALTER TABLE`` blocks behind any open transaction touching the table — and
#: while it waits, every *later* query on that table queues behind it, because
#: PostgreSQL grants lock requests in order. A long-running report can
#: therefore stall the whole table through a migration that would have taken a
#: millisecond. Giving up after a few seconds turns that into a retryable
#: deploy instead of an incident.
LOCK_TIMEOUT_ENV_VAR = "EHEALTH_MIGRATION_LOCK_TIMEOUT"
DEFAULT_LOCK_TIMEOUT = "5s"

#: Ceiling on any single migration statement. Zero means no limit, which is
#: the default: a legitimate index build on a national-scale table can run for
#: hours and must not be killed halfway through.
STATEMENT_TIMEOUT_ENV_VAR = "EHEALTH_MIGRATION_STATEMENT_TIMEOUT"
DEFAULT_STATEMENT_TIMEOUT = "0"

_DURATION = re.compile(r"\d{1,9}(ms|s|min|h)?")


def guard_migration(connection) -> None:
    """Take the migration lock and bound how long locks are waited for.

    A no-op on anything but PostgreSQL — SQLite has a single writer anyway, so
    there is no second migrator to exclude.

    Two deployers migrating simultaneously is not hypothetical: it is what a
    retried pipeline, or a rolling deploy across two regions, does by default.
    Without the lock both proceed, and the loser fails somewhere in the middle
    with no transaction left to roll back whatever ran non-transactionally.

    ``pg_try_advisory_lock`` returns rather than blocks, so the second deployer
    reports the collision immediately instead of hanging until someone thinks
    to look for it.
    """
    if connection.dialect.name != "postgresql":
        return

    acquired = connection.exec_driver_sql(
        f"select pg_try_advisory_lock({MIGRATION_LOCK_KEY})"
    ).scalar()
    if not acquired:
        raise ConcurrentMigration(
            "another migration is already running against this database "
            "(advisory lock held). Wait for it to finish rather than forcing "
            "this one through: two concurrent migrations can leave the schema "
            "in a state neither of them describes."
        )

    lock_timeout = os.environ.get(LOCK_TIMEOUT_ENV_VAR, DEFAULT_LOCK_TIMEOUT)
    statement_timeout = os.environ.get(
        STATEMENT_TIMEOUT_ENV_VAR, DEFAULT_STATEMENT_TIMEOUT
    )
    # SET does not accept bound parameters, so the values are interpolated —
    # and therefore validated first, even though they come from the
    # deployer's own environment. A PostgreSQL duration: digits and a unit.
    for name, value in (("lock", lock_timeout), ("statement", statement_timeout)):
        if not _DURATION.fullmatch(value):
            raise ValueError(f"invalid {name} timeout {value!r}; use e.g. 5s or 500ms")
    connection.execute(text(f"set lock_timeout = '{lock_timeout}'"))
    connection.execute(text(f"set statement_timeout = '{statement_timeout}'"))

    # Those statements opened an implicit transaction. Leaving it open makes
    # alembic's own `begin_transaction()` nest inside it, so the migration is
    # never committed and the database comes back empty with every command
    # reporting success — a silent no-op, which is the worst possible outcome
    # for a migration tool. Ending it here is safe: both the advisory lock and
    # a plain SET are session-scoped, not transaction-scoped, so they outlive
    # the commit and still cover the migration that follows.
    connection.commit()


class SchemaMetadata(Base):
    """One row, stating which schema version the database is at.

    Alembic's own ``alembic_version`` tracks the *revision*, which is a hash
    and means nothing to a human or to the compatibility table in the
    changelog. This is the number the application, ``GET /v1/version`` and the
    release notes all talk about.
    """

    __tablename__ = "schema_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    #: The build that last migrated, for tracing an upgrade after the fact.
    applied_by: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    applied_at: Mapped[object] = mapped_column(
        UtcDateTime, nullable=False, default=utcnow
    )


@dataclass(frozen=True, slots=True)
class SchemaState:
    database_version: int | None
    code_version: int
    #: ``None`` when the table is absent, which means "never migrated".
    initialised: bool

    @property
    def matches(self) -> bool:
        return self.database_version == self.code_version

    @property
    def needs_upgrade(self) -> bool:
        return self.database_version is not None and (
            self.database_version < self.code_version
        )

    @property
    def code_is_stale(self) -> bool:
        return self.database_version is not None and (
            self.database_version > self.code_version
        )


def read_schema_state(engine: Engine) -> SchemaState:
    table_name = SchemaMetadata.__tablename__
    if table_name not in inspect(engine).get_table_names():
        return SchemaState(None, SCHEMA_VERSION, initialised=False)
    with engine.connect() as connection:
        version = connection.execute(
            select(SchemaMetadata.__table__.c.schema_version)
            .order_by(SchemaMetadata.__table__.c.id)
            .limit(1)
        ).scalar()
    return SchemaState(version, SCHEMA_VERSION, initialised=version is not None)


def stamp_schema_version(
    connection, version: int = SCHEMA_VERSION, applied_by: str = ""
) -> None:
    """Record the schema version. Called from migrations, not from the app.

    Takes a live connection rather than an engine so a migration can stamp
    inside its own transaction — the version and the DDL it describes land
    together or not at all.
    """
    table: Table = SchemaMetadata.__table__
    existing = connection.execute(select(table.c.id).limit(1)).scalar()
    values = {
        "schema_version": version,
        "applied_by": (applied_by or "")[:40],
        "applied_at": utcnow(),
    }
    if existing is None:
        connection.execute(table.insert().values(id=1, **values))
    else:
        connection.execute(
            table.update().where(table.c.id == existing).values(**values)
        )


def require_matching_schema(engine: Engine) -> SchemaState:
    """Refuse to run against a schema this build does not expect."""
    state = read_schema_state(engine)
    if not state.initialised:
        raise SchemaMismatch(
            "the database has no schema version: it has never been migrated. "
            "Run `make migrate` (alembic upgrade head)."
        )
    if state.needs_upgrade:
        raise SchemaMismatch(
            f"database is at schema version {state.database_version}, this build "
            f"expects {state.code_version}. Run `make migrate`."
        )
    if state.code_is_stale:
        raise SchemaMismatch(
            f"database is at schema version {state.database_version}, which is "
            f"newer than this build's {state.code_version}. This build is older "
            f"than the data and must not write to it — deploy the matching "
            f"version, or roll the database back deliberately."
        )
    return state
