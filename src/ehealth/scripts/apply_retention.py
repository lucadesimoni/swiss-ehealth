# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Apply the retention period (EPDV art. 10). Dry run unless ``--apply``.

Run from a scheduler, daily is plenty. See ``services/retention.py`` for what
is destroyed and what is deliberately kept.
"""

from __future__ import annotations

import argparse

from ehealth.config import get_settings
from ehealth.container import build_container
from ehealth.db import get_session_factory, init_engine
from ehealth.services.audit import ActorContext


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apply", action="store_true", help="actually destroy")
    arguments = parser.parse_args()

    settings = get_settings()
    init_engine(settings)
    container = build_container(settings)
    with get_session_factory()() as session:
        results = container.retention.apply(
            session,
            ActorContext.system(request_id="retention-job"),
            dry_run=not arguments.apply,
        )
        session.commit()
    verb = "destroyed" if arguments.apply else "would destroy"
    for result in results:
        print(
            f"{result.dossier_uid}: {verb} {result.documents} documents, "
            f"{result.medications} medication entries, {result.revisions} revisions"
        )
    print(
        f"{len(results)} dossier(s) past retention"
        + ("" if arguments.apply else " (dry run)")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
