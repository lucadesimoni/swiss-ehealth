# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Oversized bodies are refused before any application code reads them."""

from __future__ import annotations

import pytest

from ehealth.api.limits import DEFAULT_LIMIT, DOCUMENT_LIMIT, limit_for
from ehealth.schema import guard_migration


class TestBodySizeLimit:
    def test_an_anonymous_oversized_body_is_refused(self, client):
        """The attack this exists for: gigabytes to a public login endpoint,
        which would otherwise be read in full before any check."""
        client.headers.pop("X-Admin-Key", None)
        response = client.post(
            "/v1/auth/callback",
            content=b"x" * (DEFAULT_LIMIT + 1),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 413
        assert response.headers["content-type"] == "application/problem+json"

    def test_a_chunked_body_without_a_length_is_counted_too(self, client):
        def stream():
            for _ in range(DEFAULT_LIMIT // 65536 + 2):
                yield b"x" * 65536

        response = client.post(
            "/v1/auth/callback",
            content=stream(),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 413

    def test_a_lying_content_length_is_refused(self, client):
        response = client.post(
            "/v1/auth/callback", content=b"{}", headers={"content-length": "nonsense"}
        )
        assert response.status_code in (400, 413)

    def test_ordinary_requests_are_untouched(self, client):
        assert client.get("/health").status_code == 200

    @pytest.mark.parametrize(
        ("method", "path", "expected"),
        [
            ("POST", "/v1/fhir", DOCUMENT_LIMIT),
            ("POST", "/v1/fhir/", DOCUMENT_LIMIT),
            ("POST", "/v1/dossiers/dos_1/documents", DOCUMENT_LIMIT),
            ("POST", "/v1/fhir/Patient/$match", DEFAULT_LIMIT),
            ("POST", "/v1/auth/callback", DEFAULT_LIMIT),
            ("GET", "/v1/fhir", DEFAULT_LIMIT),
        ],
    )
    def test_only_document_routes_get_the_large_limit(self, method, path, expected):
        assert limit_for(method, path) == expected


class TestMigrationTimeoutValidation:
    @pytest.mark.parametrize("value", ["5s'; drop table person; --", "5 s", "", "-1"])
    def test_a_timeout_that_is_not_a_duration_is_refused(self, value, monkeypatch):
        class FakePostgres:
            class dialect:
                name = "postgresql"

            def exec_driver_sql(self, sql):
                class Result:
                    def scalar(self):
                        return True

                return Result()

            def execute(self, statement):
                raise AssertionError(f"reached SQL with {value!r}")

        monkeypatch.setenv("EHEALTH_MIGRATION_LOCK_TIMEOUT", value)
        with pytest.raises(ValueError, match="invalid lock timeout"):
            guard_migration(FakePostgres())
