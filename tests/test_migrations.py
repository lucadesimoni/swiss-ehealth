# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Migrations, and the guard that stops a build serving the wrong schema.

The test that earns its keep is :meth:`TestNoDrift.test_migrations_match_the_models`.
Migrations drift from models silently — someone adds a column, runs the test
suite (which uses ``create_all``), and everything passes while production is
missing the column. This runs the migrations on an empty database and asks
alembic itself whether anything differs.
"""

from __future__ import annotations

import pathlib

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from ehealth.db import Base
from ehealth.schema import (
    SchemaMismatch,
    read_schema_state,
    require_matching_schema,
    stamp_schema_version,
)
from ehealth.version import SCHEMA_VERSION

import ehealth.models  # noqa: F401  (registers every table)

REPO = pathlib.Path(__file__).resolve().parents[1]


def alembic_config(database_url: str) -> Config:
    config = Config(str(REPO / "alembic.ini"))
    config.set_main_option("script_location", str(REPO / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def migrated_url(tmp_path, monkeypatch) -> str:
    """An empty database brought up entirely by migrations."""
    url = f"sqlite+pysqlite:///{tmp_path / 'migrated.db'}"
    monkeypatch.setenv("EHEALTH_DATABASE_URL", url)
    from ehealth.config import get_settings

    get_settings.cache_clear()
    try:
        command.upgrade(alembic_config(url), "head")
    finally:
        get_settings.cache_clear()
    return url


class TestNoDrift:
    def test_migrations_match_the_models(self, migrated_url):
        """The check that stops the classic silent failure.

        Tests build their schema with ``create_all``, so a model change with no
        migration passes every other test in this suite and only breaks in
        production, where ``create_all`` never runs.
        """
        engine = create_engine(migrated_url)
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={
                    "compare_type": True,
                    "compare_server_default": True,
                    "include_object": lambda obj, name, type_, reflected, compare_to: (
                        not (type_ == "table" and name == "alembic_version")
                    ),
                },
            )
            differences = compare_metadata(context, Base.metadata)

        assert not differences, (
            "the migrations and the models disagree. Run:\n"
            "  make migration name='describe the change'\n"
            f"differences: {differences}"
        )

    def test_migrations_create_every_table(self, migrated_url):
        engine = create_engine(migrated_url)
        produced = set(inspect(engine).get_table_names()) - {"alembic_version"}
        assert produced == set(Base.metadata.tables)

    def test_there_is_exactly_one_head(self):
        """Two heads mean two people migrated in parallel and nobody merged —
        the next `upgrade head` then fails for everyone."""
        from alembic.script import ScriptDirectory

        script = ScriptDirectory.from_config(alembic_config("sqlite://"))
        assert len(script.get_heads()) == 1, script.get_heads()


class TestSchemaStamp:
    def test_migrating_stamps_the_version_and_the_build(self, migrated_url):
        engine = create_engine(migrated_url)
        state = read_schema_state(engine)
        assert state.database_version == SCHEMA_VERSION
        assert state.matches

        with engine.connect() as connection:
            applied_by = connection.execute(
                text("select applied_by from schema_metadata")
            ).scalar()
        # Traceable to the build that ran the migration.
        assert applied_by.startswith("0.")

    def test_create_all_stamps_too(self, container):
        """The development path must leave a database the guard accepts."""
        from ehealth.db import get_engine

        assert read_schema_state(get_engine()).matches


class TestBootGuard:
    """Serving a schema the build does not expect is how records get corrupted
    quietly, so both directions are refused at boot."""

    def test_accepts_a_matching_schema(self, migrated_url):
        engine = create_engine(migrated_url)
        assert require_matching_schema(engine).matches

    def test_refuses_a_database_that_was_never_migrated(self, tmp_path):
        engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'empty.db'}")
        with pytest.raises(SchemaMismatch, match="never been migrated"):
            require_matching_schema(engine)

    def test_refuses_when_migrations_are_pending(self, migrated_url):
        engine = create_engine(migrated_url)
        with engine.begin() as connection:
            stamp_schema_version(connection, SCHEMA_VERSION - 1)
        with pytest.raises(SchemaMismatch, match="Run `make migrate`"):
            require_matching_schema(engine)

    def test_refuses_when_the_build_is_older_than_the_data(self, migrated_url):
        """A rollback that skipped its migration. The old code does not know
        about columns the new schema requires, so writing through it can drop
        data silently."""
        engine = create_engine(migrated_url)
        with engine.begin() as connection:
            stamp_schema_version(connection, SCHEMA_VERSION + 1)
        with pytest.raises(SchemaMismatch, match="older than the data"):
            require_matching_schema(engine)

    def test_stamping_is_idempotent(self, migrated_url):
        engine = create_engine(migrated_url)
        with engine.begin() as connection:
            stamp_schema_version(connection)
            stamp_schema_version(connection)
        with engine.connect() as connection:
            rows = connection.execute(text("select count(*) from schema_metadata"))
            assert rows.scalar() == 1


class TestMigrationHygiene:
    def test_the_initial_migration_refuses_to_downgrade(self):
        """Dropping every table is not a rollback, it is data loss with extra
        steps."""
        versions = sorted((REPO / "migrations" / "versions").glob("*.py"))
        assert versions, "no migrations found"
        initial = versions[0].read_text()
        assert "NotImplementedError" in initial
        assert "restore from backup" in initial

    def test_every_migration_carries_the_licence_header(self):
        for path in (REPO / "migrations").rglob("*.py"):
            assert "SPDX-License-Identifier: AGPL-3.0-or-later" in path.read_text(), (
                path
            )
