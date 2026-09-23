# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Deployment configuration.

Defaults are the *safe* values, so an operator has to opt in to anything
weaker rather than remember to turn protections on.
"""

from __future__ import annotations

import os
import re
from enum import StrEnum
from functools import lru_cache

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ehealth.security.crypto import KeyPurpose, KeyRing, b64u


class Environment(StrEnum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"


class DataRegion(StrEnum):
    """Where data at rest is allowed to live.

    Swiss health data under EPDG/EPDV and the revised DSG is kept on Swiss
    infrastructure; the enum exists so the choice is explicit and auditable
    rather than implied by a connection string.
    """

    CH = "ch"
    CH_LI = "ch-li"


#: Name under which the flat ``EHEALTH_SWISSID_*`` settings are registered.
SWISSID = "swissid"

_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


class IdentityProviderSettings(BaseModel):
    """One federated identity provider: SwissID, HIN, a community IdP.

    Every provider carries its own assurance policy, because the level names
    are the provider's own vocabulary — SwissID and HIN do not share one — and
    because "strong enough for a health record" is a decision per provider,
    not a global switch.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    issuer: str
    client_id: str = ""
    client_secret: str = Field(default="", repr=False)
    redirect_uri: str = "https://dossier.example.ch/auth/callback"
    scopes: tuple[str, ...] = ("openid", "profile", "email")
    #: Levels of assurance requested via ``acr_values``.
    acr_values: tuple[str, ...] = ()
    #: The ``acr`` values a login must carry to be accepted at all. Empty
    #: accepts any level, which production refuses.
    accepted_acr: tuple[str, ...] = ()
    #: ``acr`` values that already prove two factors at the provider. A login
    #: at one of these is complete without the emailed code; below them the
    #: emailed code is the second factor.
    mfa_acr: tuple[str, ...] = ()
    #: Stricter set for people holding the healthcare-professional role.
    #: Empty means professionals are held to ``accepted_acr`` like everyone.
    professional_acr: tuple[str, ...] = ()
    client_auth_method: str = "client_secret_post"
    private_key_pem: str = Field(default="", repr=False)
    private_key_id: str = ""

    @field_validator("name")
    @classmethod
    def _valid_name(cls, value: str) -> str:
        if not _PROVIDER_NAME.match(value):
            raise ValueError(
                "provider name must be lowercase letters, digits and dashes, "
                "starting with a letter, 2-32 characters"
            )
        return value

    @model_validator(mode="after")
    def _consistent_policy(self) -> IdentityProviderSettings:
        accepted = set(self.accepted_acr)
        if accepted:
            # A level strong enough to skip the second factor, or required of
            # professionals, that is not also *accepted* would be unreachable:
            # the login would be refused before the stronger rule applied.
            for label, values in (
                ("mfa_acr", self.mfa_acr),
                ("professional_acr", self.professional_acr),
            ):
                stray = set(values) - accepted
                if stray:
                    raise ValueError(
                        f"{self.name}: {label} {sorted(stray)} is not in accepted_acr"
                    )
        if self.client_auth_method not in {"client_secret_post", "private_key_jwt"}:
            raise ValueError(
                f"{self.name}: unknown client_auth_method {self.client_auth_method!r}"
            )
        return self

    def credential_problems(self) -> list[str]:
        """What stops this provider working against a real endpoint."""
        problems = []
        if not self.client_id:
            problems.append(f"{self.name}: client_id is not set")
        if self.client_auth_method == "private_key_jwt":
            if not self.private_key_pem:
                problems.append(f"{self.name}: private_key_jwt needs a private key")
        elif not self.client_secret:
            problems.append(f"{self.name}: client secret is not set")
        return problems


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EHEALTH_", env_file=".env", extra="ignore"
    )

    environment: Environment = Environment.LOCAL
    service_name: str = "ch.ehealth.dossier"
    issuer: str = "https://dossier.example.ch"
    database_url: str = "sqlite+pysqlite:///./ehealth.db"

    # -- sovereignty ------------------------------------------------------
    data_region: DataRegion = DataRegion.CH
    #: Hostname suffixes any outbound processor must match. Empty disables the
    #: check, which is only sensible locally.
    allowed_processor_domains: tuple[str, ...] = (".ch", ".swiss")

    # -- key material -----------------------------------------------------
    #: base64url, >=32 bytes. In production this comes from an HSM/KMS backed
    #: secret, never from a file in the repository.
    root_key: str = ""
    key_version_field_encryption: int = 1
    key_version_lookup_index: int = 1
    key_version_token_signing: int = 1
    key_version_audit_ledger: int = 1

    #: Keep an AEAD-sealed copy of the AHVN13 so blind indices can be rebuilt
    #: and lawful disclosure can be answered. Set to False for a
    #: zero-retention deployment (rotation then requires re-enrolment).
    store_sealed_ahvn: bool = True

    # -- tokens -----------------------------------------------------------
    session_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 60 * 60 * 12
    capability_token_ttl_seconds: int = 600
    visitor_token_ttl_seconds: int = 60 * 60 * 4
    emergency_token_ttl_seconds: int = 60 * 60 * 2
    #: Reject tokens whose lifetime exceeds this, whatever the request asked.
    max_token_ttl_seconds: int = 60 * 60 * 24
    clock_skew_seconds: int = 30

    # -- authentication ---------------------------------------------------
    swissid_issuer: str = "https://login.swissid.ch"
    swissid_client_id: str = ""
    swissid_client_secret: str = ""
    swissid_redirect_uri: str = "https://dossier.example.ch/auth/callback"
    swissid_scopes: tuple[str, ...] = ("openid", "profile", "email")
    #: See :class:`IdentityProviderSettings` for what each of these means.
    swissid_acr_values: tuple[str, ...] = ()
    swissid_accepted_acr: tuple[str, ...] = ()
    swissid_mfa_acr: tuple[str, ...] = ()
    swissid_professional_acr: tuple[str, ...] = ()
    swissid_client_auth_method: str = "client_secret_post"
    swissid_private_key_pem: str = Field(default="", repr=False)
    swissid_private_key_id: str = ""
    #: Further providers — HIN for professionals, a community IdP — as a JSON
    #: list of :class:`IdentityProviderSettings` objects in
    #: ``EHEALTH_EXTRA_IDENTITY_PROVIDERS``.
    extra_identity_providers: tuple[IdentityProviderSettings, ...] = ()
    #: Use the in-process fake identity provider. Refused in production.
    use_mock_idp: bool = True

    otp_length: int = 6
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5
    otp_resend_cooldown_seconds: int = 30
    login_max_attempts_per_hour: int = 10

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_from: str = "noreply@dossier.example.ch"

    #: Shared secret for the enrolment/administration endpoints, which are
    #: called by back-office systems rather than by a logged-in person.
    #: Empty disables those endpoints entirely, which is the right default.
    admin_api_key: str = ""

    # -- retention --------------------------------------------------------
    #: EPDV art. 10: records are kept for 20 years after the last entry.
    dossier_retention_years: int = 20
    #: Audit trail retention. Kept at least as long as the data it describes.
    audit_retention_years: int = 20

    @field_validator("root_key")
    @classmethod
    def _non_empty_in_production(cls, value: str) -> str:
        return value.strip()

    @model_validator(mode="after")
    def _production_hardening(self) -> Settings:
        if self.environment is Environment.PRODUCTION:
            problems = []
            if not self.root_key:
                problems.append("EHEALTH_ROOT_KEY must be set")
            if self.use_mock_idp:
                problems.append("the mock identity provider must be disabled")
            for provider in self.identity_providers():
                problems.extend(provider.credential_problems())
                if not provider.accepted_acr:
                    # Without it any login the provider completes is accepted,
                    # including one that only proved control of a mailbox.
                    problems.append(
                        f"{provider.name}: accepted_acr must list the levels of "
                        f"assurance a login needs"
                    )
            if self.issuer.startswith("http://"):
                problems.append("issuer must be https")
            if self.database_url.startswith("sqlite"):
                problems.append("sqlite is not a supported production database")
            if self.admin_api_key and len(self.admin_api_key) < 32:
                problems.append("admin API key must be at least 32 characters")
            if problems:
                raise ValueError(
                    "refusing to start in production: " + "; ".join(problems)
                )
        names = [provider.name for provider in self.identity_providers()]
        if len(names) != len(set(names)):
            raise ValueError(f"identity provider names must be unique: {names}")
        if self.max_token_ttl_seconds < max(
            self.session_token_ttl_seconds,
            self.capability_token_ttl_seconds,
            self.visitor_token_ttl_seconds,
            self.emergency_token_ttl_seconds,
        ):
            raise ValueError("max_token_ttl_seconds is below a configured token TTL")
        return self

    # -- derived ----------------------------------------------------------

    def identity_providers(self) -> tuple[IdentityProviderSettings, ...]:
        """Every configured provider, SwissID first."""
        swissid = IdentityProviderSettings(
            name=SWISSID,
            issuer=self.swissid_issuer,
            client_id=self.swissid_client_id,
            client_secret=self.swissid_client_secret,
            redirect_uri=self.swissid_redirect_uri,
            scopes=self.swissid_scopes,
            acr_values=self.swissid_acr_values,
            accepted_acr=self.swissid_accepted_acr,
            mfa_acr=self.swissid_mfa_acr,
            professional_acr=self.swissid_professional_acr,
            client_auth_method=self.swissid_client_auth_method,
            private_key_pem=self.swissid_private_key_pem,
            private_key_id=self.swissid_private_key_id,
        )
        return (swissid, *self.extra_identity_providers)

    def keyring(self) -> KeyRing:
        """Build the keyring. Generates an ephemeral root key outside
        production so a developer checkout runs without ceremony — and so a
        forgotten key never silently protects real data."""
        versions = {
            KeyPurpose.FIELD_ENCRYPTION: self.key_version_field_encryption,
            KeyPurpose.PERSON_LOOKUP_INDEX: self.key_version_lookup_index,
            KeyPurpose.TOKEN_SIGNING: self.key_version_token_signing,
            KeyPurpose.AUDIT_LEDGER: self.key_version_audit_ledger,
        }
        if self.root_key:
            return KeyRing.from_base64(self.root_key, versions)
        if self.environment is Environment.PRODUCTION:  # pragma: no cover
            raise RuntimeError("no root key configured")
        return KeyRing(os.urandom(32), versions)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def generate_root_key() -> str:
    """Helper for ``make keygen`` — prints a fresh root key."""
    return b64u(os.urandom(32))
