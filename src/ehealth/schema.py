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

from dataclasses import dataclass

from sqlalchemy import Engine, Integer, String, Table, inspect, select
from sqlalchemy.orm import Mapped, mapped_column

from ehealth.db import Base, utcnow
from ehealth.models.base import UtcDateTime
from ehealth.version import SCHEMA_VERSION


class SchemaMismatch(RuntimeError):
    """The database is not the shape this build expects."""


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
        connection.execute(table.update().where(table.c.id == existing).values(**values))


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
