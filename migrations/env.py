# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Alembic environment.

The connection string comes from the application's own settings rather than
``alembic.ini``, so there is exactly one place a database URL lives and no way
to migrate one database while the application talks to another.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from ehealth.config import get_settings
from ehealth.db import Base

# Importing the package registers every table on the metadata; without it
# autogenerate would cheerfully propose dropping tables it cannot see.
import ehealth.models  # noqa: F401

config = context.config
target_metadata = Base.metadata

config.set_main_option(
    "sqlalchemy.url", get_settings().database_url.replace("%", "%%")
)


def _include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Keep alembic's own bookkeeping table out of autogenerate."""
    return not (type_ == "table" and name == "alembic_version")


def _render_item(type_, obj, autogen_context):
    """Render the project's own column types by name.

    Autogenerate would otherwise inline them — ``JSON().with_variant(JSONB(
    astext_type=Text()), 'postgresql')`` — which needs three more imports and
    is unreadable in a diff. Both are thin, stable aliases over standard
    types, so naming them keeps migrations legible without hiding anything:
    a change to either is a schema change and needs its own migration anyway.
    """
    import sqlalchemy as sa

    from ehealth.models.base import UtcDateTime

    if type_ == "type":
        if isinstance(obj, UtcDateTime):
            autogen_context.imports.add("import ehealth.models.base")
            return "ehealth.models.base.UtcDateTime()"
        if isinstance(obj, sa.JSON) and getattr(obj, "_variant_mapping", None):
            autogen_context.imports.add("import ehealth.models.base")
            return "ehealth.models.base.JsonType"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
        render_item=_render_item,
        # Without this, SQLite cannot ALTER most things; with it, alembic
        # rebuilds the table instead. Harmless on PostgreSQL.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=_include_object,
            render_item=_render_item,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
