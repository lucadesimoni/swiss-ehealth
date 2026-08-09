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

import ehealth.models  # noqa: F401  (registers every table)
from ehealth.db import Base
from ehealth.schema import (
    MIGRATION_LOCK_KEY,
    ConcurrentMigration,
    SchemaMismatch,
    read_schema_state,
    require_matching_schema,
    stamp_schema_version,
)
from ehealth.version import SCHEMA_VERSION

REPO = pathlib.Path(__file__).resolve().parents[1]


def alembic_config(database_url: str) -> Config:
    config = Config(str(REPO / "alembic.ini"))
    config.set_main_option("script_location", str(REPO / "migrations"))
    # alembic.ini is read by configparser, which treats `%` as interpolation.
    # Percent-encoded URLs and passwords containing `%` both hit this, and the
    # error names configparser rather than the URL. `migrations/env.py` escapes
    # the same way for the same reason.
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


@pytest.fixture
def migrated_url(database_url, monkeypatch) -> str:
    """An empty database brought up entirely by migrations.

    Takes whichever backend the suite is configured for, so setting
    ``EHEALTH_TEST_DATABASE_URL`` runs the migrations — and the drift check —
    against PostgreSQL. SQLite is the convenient default; PostgreSQL is what
    production uses, and only it can catch a JSONB mismatch or a type that
    reflects back differently than it was declared.
    """
    monkeypatch.setenv("EHEALTH_DATABASE_URL", database_url)
    from ehealth.config import get_settings

    get_settings.cache_clear()
    try:
        command.upgrade(alembic_config(database_url), "head")
    finally:
        get_settings.cache_clear()
    return database_url


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


class TestConcurrencyGuard:
    """Two deployers migrating at once is what a retried pipeline does by
    default. Without the lock both run, and the loser fails partway through."""

    @pytest.fixture
    def postgres_connection(self, database_url):
        if not database_url.startswith("postgresql"):
            pytest.skip("advisory locks are a PostgreSQL feature")
        engine = create_engine(database_url)
        with engine.connect() as connection:
            yield connection
        engine.dispose()

    def test_a_second_migrator_is_refused_rather_than_left_to_hang(
        self, postgres_connection, database_url, monkeypatch
    ):
        """The holder is simulated with the same advisory lock the migration
        takes, which is what a real concurrent `alembic upgrade` would hold."""
        held = postgres_connection.exec_driver_sql(
            f"select pg_try_advisory_lock({MIGRATION_LOCK_KEY})"
        ).scalar()
        assert held, "could not take the lock to set the test up"

        monkeypatch.setenv("EHEALTH_DATABASE_URL", database_url)
        from ehealth.config import get_settings

        get_settings.cache_clear()
        try:
            with pytest.raises(ConcurrentMigration, match="another migration"):
                command.upgrade(alembic_config(database_url), "head")
        finally:
            get_settings.cache_clear()
            postgres_connection.exec_driver_sql(
                f"select pg_advisory_unlock({MIGRATION_LOCK_KEY})"
            )

    def test_the_lock_is_released_so_the_next_migration_can_run(
        self, migrated_url, database_url
    ):
        """A lock that outlived its migration would block every later deploy
        until someone found and killed the session."""
        if not database_url.startswith("postgresql"):
            pytest.skip("advisory locks are a PostgreSQL feature")
        engine = create_engine(database_url)
        with engine.connect() as connection:
            free = connection.exec_driver_sql(
                f"select pg_try_advisory_lock({MIGRATION_LOCK_KEY})"
            ).scalar()
            connection.exec_driver_sql(
                f"select pg_advisory_unlock({MIGRATION_LOCK_KEY})"
            )
        engine.dispose()
        assert free, "the migration left its advisory lock held"


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
