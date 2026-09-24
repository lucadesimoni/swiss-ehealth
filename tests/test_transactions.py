# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""A write the database did not keep must never be acknowledged."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.db import get_session_factory
from ehealth.models.core import Person


class TestCommitFailure:
    def test_a_failed_commit_is_not_reported_as_success(
        self, client, container, monkeypatch
    ):
        """With FastAPI's default dependency scope the commit ran after the
        response was built, so a commit failure still reached the client as
        200 — a registration acknowledged and then rolled back."""

        def refuse(self):
            raise RuntimeError("simulated commit failure (e.g. serialization)")

        monkeypatch.setattr(Session, "commit", refuse)
        with pytest.raises(RuntimeError, match="simulated commit failure"):
            client.post(
                "/v1/persons",
                json={
                    "roles": ["patient"],
                    "given_name": "Nie",
                    "family_name": "Gespeichert",
                    "identification_method": "passport",
                },
            )
        monkeypatch.undo()
        with get_session_factory()() as db:
            assert db.execute(select(Person)).first() is None

    def test_a_server_error_is_a_5xx_not_a_200(self, settings, container, monkeypatch):
        from fastapi.testclient import TestClient

        from ehealth.main import create_app
        from tests.conftest import ADMIN_KEY

        def refuse(self):
            raise RuntimeError("simulated commit failure")

        monkeypatch.setattr(Session, "commit", refuse)
        app = create_app(settings, container=container)
        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.post(
                "/v1/persons",
                headers={"X-Admin-Key": ADMIN_KEY},
                json={
                    "roles": ["patient"],
                    "given_name": "Nie",
                    "family_name": "Gespeichert",
                    "identification_method": "passport",
                },
            )
        assert response.status_code >= 500
