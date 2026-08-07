"""Deployment configuration must fail closed."""

from __future__ import annotations

import pytest

from ehealth.config import DataRegion, Environment, Settings, generate_root_key
from ehealth.security.crypto import KeyPurpose, b64u_decode
from ehealth.security.oidc import MockIdentityProvider, OidcError

PROD = dict(
    environment=Environment.PRODUCTION,
    root_key=generate_root_key(),
    use_mock_idp=False,
    swissid_client_id="client",
    swissid_client_secret="secret",
    issuer="https://dossier.example.ch",
    database_url="postgresql+psycopg://user@db.local/ehealth",
)


class TestProductionHardening:
    def test_a_correct_production_config_is_accepted(self):
        assert Settings(**PROD).environment is Environment.PRODUCTION

    def test_refuses_to_start_without_a_root_key(self):
        with pytest.raises(ValueError, match="ROOT_KEY"):
            Settings(**{**PROD, "root_key": ""})

    def test_refuses_the_mock_identity_provider(self):
        """The "we forgot to turn off the fake login" outage, prevented at
        configuration time rather than by discipline."""
        with pytest.raises(ValueError, match="mock identity provider"):
            Settings(**{**PROD, "use_mock_idp": True})

    def test_refuses_missing_swissid_credentials(self):
        with pytest.raises(ValueError, match="SwissID"):
            Settings(**{**PROD, "swissid_client_secret": ""})

    def test_refuses_plaintext_http(self):
        with pytest.raises(ValueError, match="https"):
            Settings(**{**PROD, "issuer": "http://dossier.example.ch"})

    def test_refuses_sqlite(self):
        with pytest.raises(ValueError, match="sqlite"):
            Settings(**{**PROD, "database_url": "sqlite+pysqlite:///./prod.db"})

    def test_refuses_a_short_admin_key(self):
        with pytest.raises(ValueError, match="admin API key"):
            Settings(**{**PROD, "admin_api_key": "short"})

    def test_reports_every_problem_at_once(self):
        with pytest.raises(ValueError) as excinfo:
            Settings(
                environment=Environment.PRODUCTION,
                root_key="",
                use_mock_idp=True,
                database_url="sqlite+pysqlite:///./prod.db",
            )
        message = str(excinfo.value)
        assert "ROOT_KEY" in message and "mock identity provider" in message


class TestTokenLifetimes:
    def test_rejects_a_ttl_above_the_ceiling(self):
        with pytest.raises(ValueError, match="max_token_ttl_seconds"):
            Settings(max_token_ttl_seconds=60, visitor_token_ttl_seconds=3600)


class TestDefaults:
    def test_defaults_are_the_safe_values(self):
        settings = Settings()
        assert settings.data_region is DataRegion.CH
        assert settings.store_sealed_ahvn is True
        assert settings.admin_api_key == ""  # enrolment endpoints off by default
        assert settings.dossier_retention_years == 20
        assert settings.session_token_ttl_seconds <= 900

    def test_local_runs_generate_an_ephemeral_key(self):
        """A developer checkout must run without ceremony, and a forgotten key
        must never silently protect real data."""
        first = Settings().keyring().key(KeyPurpose.FIELD_ENCRYPTION).material
        second = Settings().keyring().key(KeyPurpose.FIELD_ENCRYPTION).material
        assert first != second

    def test_a_configured_root_key_is_used_verbatim(self):
        key = generate_root_key()
        settings = Settings(root_key=key)
        assert len(b64u_decode(key)) == 32
        assert (
            settings.keyring().key(KeyPurpose.FIELD_ENCRYPTION).material
            == Settings(root_key=key).keyring().key(KeyPurpose.FIELD_ENCRYPTION).material
        )

    def test_key_versions_flow_into_the_keyring(self):
        keyring = Settings(key_version_field_encryption=4).keyring()
        assert keyring.current_version(KeyPurpose.FIELD_ENCRYPTION) == 4


def test_the_mock_provider_refuses_to_exist_in_production():
    with pytest.raises(OidcError, match="production"):
        MockIdentityProvider(production=True)
