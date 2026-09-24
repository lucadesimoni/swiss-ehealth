# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Rehearse a restore: back up a PostgreSQL database, restore it into an
empty one, and prove the copy is whole.

A backup that has never been restored is a hope, not a backup. This does the
full round trip the way an operator would in an incident, and then checks
what an operator would otherwise have to take on faith:

1. ``pg_dump`` the source (custom format, the one ``pg_restore`` reads);
2. ``pg_restore`` into the target, which must be empty;
3. the restored schema is the version this build expects (the boot guard's
   check) and alembic's revision matches the source's;
4. every table has the same row count as the source;
5. **every audit ledger chain verifies** in the restored copy — signatures
   and links, recomputed. A restore that silently dropped or reordered rows
   would fail here even if the counts happened to match;
6. with ``--documents DIR`` (the restored document store): **every stored
   document decrypts and matches its recorded SHA-256**. The database and the
   document store are backed up separately, and a restore that brings back
   one without the other is not a restore.

Usage::

    make restore-rehearsal SOURCE=postgresql+psycopg://… TARGET=postgresql+psycopg://…

The key material must be the same the source was written with
(``EHEALTH_ROOT_KEY``): the ledger's signatures are checked with it. That is
also the point — a backup restored without its keys is not a usable backup,
and this is where that is discovered.

Exit status 0 means the restore is proven; anything else names what failed.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from ehealth.config import get_settings
from ehealth.container import build_container
from ehealth.db import get_session_factory, init_engine
from ehealth.schema import read_schema_state


def _libpq(url: str) -> tuple[list[str], dict[str, str]]:
    """Connection arguments for pg_dump/pg_restore from a SQLAlchemy URL.

    The password goes through the environment, never the command line, where
    it would be visible in the process list.
    """
    parsed = make_url(url)
    args = []
    host = parsed.host or parsed.query.get("host")
    if host:
        args += ["--host", str(host)]
    port = parsed.port or parsed.query.get("port")
    if port:
        args += ["--port", str(port)]
    if parsed.username:
        args += ["--username", parsed.username]
    args += ["--dbname", parsed.database or ""]
    env = dict(os.environ)
    if parsed.password:
        env["PGPASSWORD"] = parsed.password
    return args, env


def _counts(url: str) -> dict[str, int]:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return {
                table: connection.execute(
                    text(f'select count(*) from "{table}"')
                ).scalar()
                for table in sorted(inspect(engine).get_table_names())
            }
    finally:
        engine.dispose()


def _revision(url: str) -> str | None:
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            return connection.execute(
                text("select version_num from alembic_version")
            ).scalar()
    finally:
        engine.dispose()


def rehearse(source: str, target: str, documents: str | None = None) -> list[str]:
    """Return the problems found; empty means the restore is proven."""
    problems: list[str] = []
    if _counts(target):
        return ["the target database is not empty; refusing to restore over data"]

    with tempfile.TemporaryDirectory() as scratch:
        dump = os.path.join(scratch, "backup.dump")
        args, env = _libpq(source)
        started = time.monotonic()
        subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--file", dump, *args],
            check=True,
            env=env,
        )
        dumped = time.monotonic() - started
        args, env = _libpq(target)
        started = time.monotonic()
        subprocess.run(
            ["pg_restore", "--no-owner", "--exit-on-error", *args, dump],
            check=True,
            env=env,
        )
        restored = time.monotonic() - started
        size = os.path.getsize(dump)
    print(f"backup {size / 1024:.0f} KiB in {dumped:.1f}s, restored in {restored:.1f}s")

    source_counts, target_counts = _counts(source), _counts(target)
    for table in sorted(set(source_counts) | set(target_counts)):
        if source_counts.get(table) != target_counts.get(table):
            problems.append(
                f"{table}: {source_counts.get(table)} rows in the source, "
                f"{target_counts.get(table)} restored"
            )
    print(f"{len(target_counts)} tables, {sum(target_counts.values())} rows compared")

    if _revision(source) != _revision(target):
        problems.append("alembic revision differs between source and restore")
    engine = create_engine(target)
    state = read_schema_state(engine)
    engine.dispose()
    if not state.matches:
        problems.append(
            f"restored schema is version {state.database_version}, "
            f"this build expects {state.code_version}"
        )

    settings = get_settings().model_copy(update={"database_url": target})
    init_engine(settings)
    container = build_container(settings)
    with get_session_factory()() as session:
        verification = container.ledger.verify_all(session)
    print(
        f"ledger: {verification.chains_checked} chains, "
        f"{verification.events_checked} events verified"
    )
    if documents is not None:
        from sqlalchemy import select

        from ehealth.models.clinical import DossierDocument
        from ehealth.services.blobstore import (
            BlobError,
            DocumentContentStore,
            FileSystemBlobStore,
        )

        store = DocumentContentStore(FileSystemBlobStore(documents), settings.keyring())
        checked = 0
        with get_session_factory()() as session:
            for document in session.execute(
                select(DossierDocument).where(
                    DossierDocument.storage_ref.like("blob:%")
                )
            ).scalars():
                checked += 1
                try:
                    store.load(document.uid, expected_sha256=document.content_hash)
                except BlobError as exc:
                    problems.append(f"document {document.uid}: {exc}")
        print(f"documents: {checked} checked against their recorded hashes")
    for failure in verification.failures:
        problems.append(
            f"ledger chain {failure.chain_id} fails at seq {failure.first_bad_seq}: "
            f"{failure.reason}"
        )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--documents", help="the restored document store directory, to verify too"
    )
    arguments = parser.parse_args()
    problems = rehearse(arguments.source, arguments.target, arguments.documents)
    for problem in problems:
        print(f"FAILED: {problem}", file=sys.stderr)
    print("restore proven" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
