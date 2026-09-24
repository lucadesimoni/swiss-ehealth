# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Deployment configuration must fail closed."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ehealth.config import (
    DataRegion,
    Environment,
    IuaClientSettings,
    Settings,
    generate_root_key,
)
from ehealth.security.crypto import KeyPurpose, b64u_decode
from ehealth.security.oidc import MockIdentityProvider, OidcError

_IUA_KEY = ec.generate_private_key(ec.SECP256R1())
IUA_KEY_PEM = _IUA_KEY.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()
CLIENT_PUBLIC_PEM = (
    ec.generate_private_key(ec.SECP256R1())
    .public_key()
    .public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    .decode()
)
SECRET_HASH = hashlib.sha256(b"a-long-random-client-secret").hexdigest()

PROD = dict(
    environment=Environment.PRODUCTION,
    root_key=generate_root_key(),
    use_mock_idp=False,
    swissid_client_id="client",
    swissid_client_secret="secret",
    swissid_accepted_acr=("loa-2", "loa-3"),
    community_patient_id_oid="2.16.756.5.30.1.999.1",
    document_store_path="/srv/ehealth/documents",
    issuer="https://dossier.example.ch",
    database_url="postgresql+psycopg://user@db.local/ehealth",
    iua_signing_key_pem=IUA_KEY_PEM,
    iua_home_community_oid="2.16.756.5.30.1.999.2",
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
        with pytest.raises(ValueError, match="swissid: client secret is not set"):
            Settings(**{**PROD, "swissid_client_secret": ""})

    def test_refuses_a_provider_with_no_required_assurance_level(self):
        """Without it, any login the provider completes is accepted —
        including one that only proved control of a mailbox."""
        with pytest.raises(ValueError, match="accepted_acr must list"):
            Settings(**{**PROD, "swissid_accepted_acr": ()})

    def test_refuses_the_placeholder_community_oid(self):
        """Publishing identifiers under the example arc would tell other
        communities they belong to a domain that does not exist."""
        with pytest.raises(ValueError, match="community_patient_id_oid"):
            Settings(**{**PROD, "community_patient_id_oid": "2.999.756.1"})

    def test_private_key_jwt_needs_a_key_not_a_secret(self):
        with pytest.raises(ValueError, match="private_key_jwt needs a private key"):
            Settings(
                **{
                    **PROD,
                    "swissid_client_secret": "",
                    "swissid_client_auth_method": "private_key_jwt",
                }
            )

    def test_refuses_plaintext_http(self):
        with pytest.raises(ValueError, match="https"):
            Settings(**{**PROD, "issuer": "http://dossier.example.ch"})

    def test_refuses_sqlite(self):
        with pytest.raises(ValueError, match="sqlite"):
            Settings(**{**PROD, "database_url": "sqlite+pysqlite:///./prod.db"})

    def test_refuses_a_short_admin_key(self):
        with pytest.raises(ValueError, match="admin API key"):
            Settings(**{**PROD, "admin_api_key": "short"})

    def test_refuses_an_ephemeral_iua_signing_key(self):
        """Every IUA token would stop verifying at the next restart."""
        with pytest.raises(ValueError, match="iua_signing_key_pem"):
            Settings(**{**PROD, "iua_signing_key_pem": ""})

    def test_refuses_unsigned_iua_token_requests(self):
        with pytest.raises(ValueError, match="RFC 9421"):
            Settings(**{**PROD, "iua_require_request_signatures": False})

    def test_refuses_the_placeholder_home_community(self):
        with pytest.raises(ValueError, match="iua_home_community_oid"):
            Settings(**{**PROD, "iua_home_community_oid": "2.999.756.2"})

    def test_refuses_an_iua_client_without_a_signing_key(self):
        client = IuaClientSettings(
            client_id="portal",
            client_secret_sha256=SECRET_HASH,
            redirect_uris=("https://portal.example.ch/cb",),
        )
        with pytest.raises(ValueError, match="public_key_pem is required"):
            Settings(**{**PROD, "iua_clients": (client,)})

    def test_accepts_a_registered_signing_iua_client(self):
        client = IuaClientSettings(
            client_id="portal",
            client_secret_sha256=SECRET_HASH,
            redirect_uris=("https://portal.example.ch/cb",),
            public_key_pem=CLIENT_PUBLIC_PEM,
        )
        assert Settings(**{**PROD, "iua_clients": (client,)}).iua_clients

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


class TestIuaClients:
    def test_the_secret_is_configured_only_as_a_hash(self):
        with pytest.raises(ValueError, match="64 hex"):
            IuaClientSettings(client_id="portal", client_secret_sha256="s3cret")

    def test_a_technical_user_needs_the_responsible_gln(self):
        with pytest.raises(ValueError, match="technical_user_gln"):
            IuaClientSettings(
                client_id="archive",
                client_secret_sha256=SECRET_HASH,
                grant_types=("client_credentials",),
            )

    def test_the_code_flow_needs_a_registered_redirect(self):
        with pytest.raises(ValueError, match="redirect_uris"):
            IuaClientSettings(client_id="portal", client_secret_sha256=SECRET_HASH)

    def test_unknown_grant_types_are_refused(self):
        with pytest.raises(ValueError, match="unknown grant types"):
            IuaClientSettings(
                client_id="portal",
                client_secret_sha256=SECRET_HASH,
                grant_types=("password",),
            )

    def test_client_ids_are_unique(self):
        client = IuaClientSettings(
            client_id="portal",
            client_secret_sha256=SECRET_HASH,
            redirect_uris=("https://portal.example.ch/cb",),
        )
        with pytest.raises(ValueError, match="unique"):
            Settings(iua_clients=(client, client))

    def test_a_weak_request_signing_key_is_refused(self):
        from cryptography.hazmat.primitives.asymmetric import rsa

        weak = (
            rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        with pytest.raises(ValueError, match="2048"):
            IuaClientSettings(
                client_id="portal",
                client_secret_sha256=SECRET_HASH,
                redirect_uris=("https://portal.example.ch/cb",),
                public_key_pem=weak,
            )


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
            == Settings(root_key=key)
            .keyring()
            .key(KeyPurpose.FIELD_ENCRYPTION)
            .material
        )

    def test_key_versions_flow_into_the_keyring(self):
        keyring = Settings(key_version_field_encryption=4).keyring()
        assert keyring.current_version(KeyPurpose.FIELD_ENCRYPTION) == 4


def test_the_mock_provider_refuses_to_exist_in_production():
    with pytest.raises(OidcError, match="production"):
        MockIdentityProvider(production=True)


class TestIdentityProviders:
    def test_swissid_comes_first_and_carries_its_policy(self):
        settings = Settings(
            swissid_accepted_acr=("loa-2", "loa-3"), swissid_mfa_acr=("loa-3",)
        )
        swissid = settings.identity_providers()[0]
        assert swissid.name == "swissid"
        assert swissid.accepted_acr == ("loa-2", "loa-3")
        assert swissid.mfa_acr == ("loa-3",)

    def test_extra_providers_are_read_from_json(self, monkeypatch):
        monkeypatch.setenv(
            "EHEALTH_EXTRA_IDENTITY_PROVIDERS",
            '[{"name": "hin", "issuer": "https://oidc.hin.ch", '
            '"accepted_acr": ["hin-2fa"], "mfa_acr": ["hin-2fa"]}]',
        )
        names = [p.name for p in Settings().identity_providers()]
        assert names == ["swissid", "hin"]

    def test_a_level_that_skips_the_second_factor_must_also_be_accepted(self):
        """Otherwise the rule is unreachable: the login is refused before it
        applies, and the configuration silently means less than it says."""
        with pytest.raises(ValueError, match=r"mfa_acr .* is not in accepted_acr"):
            Settings(swissid_accepted_acr=("loa-2",), swissid_mfa_acr=("loa-3",))

    def test_provider_names_must_be_unique(self):
        from ehealth.config import IdentityProviderSettings

        with pytest.raises(ValueError, match="must be unique"):
            Settings(
                extra_identity_providers=(
                    IdentityProviderSettings(name="swissid", issuer="https://x.ch"),
                )
            )

    @pytest.mark.parametrize("name", ["HIN", "1hin", "h", "hin provider", "a" * 33])
    def test_provider_names_are_constrained(self, name):
        from ehealth.config import IdentityProviderSettings

        with pytest.raises(ValueError, match="provider name"):
            IdentityProviderSettings(name=name, issuer="https://x.ch")

    def test_secrets_do_not_appear_in_repr(self):
        from ehealth.config import IdentityProviderSettings

        provider = IdentityProviderSettings(
            name="hin",
            issuer="https://x.ch",
            client_secret="very-secret-value",
            private_key_pem="-----BEGIN PRIVATE KEY-----",
        )
        assert "very-secret-value" not in repr(provider)
        assert "BEGIN PRIVATE KEY" not in repr(provider)
