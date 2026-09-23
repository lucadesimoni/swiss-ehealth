# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Fill ``person.demographic_index`` for people registered before schema 5.

The index is a keyed hash, so computing it needs the root key — which is
exactly why the migration that adds the column leaves it empty: a migration
must never hold key material. Run this once after ``make migrate``, with the
application's own configuration:

    make reindex-demographics

Idempotent: it only touches rows whose index is missing, so it is safe to run
again, and after a lookup-key rotation it can be run with ``--all`` to
recompute every row under the new key version.
"""

from __future__ import annotations

import argparse

from sqlalchemy import select

from ehealth.config import get_settings
from ehealth.container import build_container
from ehealth.db import get_session_factory, init_engine
from ehealth.models.core import Person


def reindex(session, identity, *, recompute_all: bool = False) -> tuple[int, int]:
    """Return (updated, skipped). Skipped rows lack a family name or a birth
    date, so there is nothing to index — they stay findable by identifier."""
    query = select(Person)
    if not recompute_all:
        query = query.where(Person.demographic_index.is_(None))
    updated = skipped = 0
    for person in session.execute(query).scalars():
        if not person.family_name_enc or person.birth_date is None:
            skipped += 1
            continue
        family = identity.open_field(person.uid, "family_name", person.family_name_enc)
        person.demographic_index = identity.demographic_index(family, person.birth_date)
        updated += 1
    session.flush()
    return updated, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--all",
        action="store_true",
        help="recompute every row, e.g. after rotating the lookup-index key",
    )
    arguments = parser.parse_args()

    settings = get_settings()
    init_engine(settings)
    container = build_container(settings)
    with get_session_factory()() as session:
        updated, skipped = reindex(
            session, container.identity, recompute_all=arguments.all
        )
        session.commit()
    print(f"{updated} indexed, {skipped} without family name or birth date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
