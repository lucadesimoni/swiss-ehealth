# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Composition root.

Every service is constructed once, here, from the settings. Nothing else in
the codebase reads configuration or builds a keyring, which means the answer
to "what key does this use, and where did it come from" is always one file.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from ehealth.config import Environment, Settings, get_settings
from ehealth.domain.identity import IdentityService
from ehealth.security.crypto import KeyRing
from ehealth.security.mfa import (
    EmailSender,
    InMemoryEmailSender,
    OtpService,
    SmtpEmailSender,
)
from ehealth.security.oidc import (
    IdentityProvider,
    MockIdentityProvider,
    OidcConfig,
    SwissIdClient,
)
from ehealth.security.tokens import TokenService
from ehealth.services.access import AccessService, ConsentService
from ehealth.services.audit import AuditLedger
from ehealth.services.auth import AuthService
from ehealth.services.changelog import ChangeTracker
from ehealth.services.dossier import DossierService
from ehealth.services.medication import MedicationCatalogue, MedicationService
from ehealth.services.offline import OfflineBundleService
from ehealth.services.persons import OrganizationService, PersonService
from ehealth.services.sync import OfflineSyncService


@dataclass(frozen=True)
class Container:
    settings: Settings
    keyring: KeyRing
    identity: IdentityService
    ledger: AuditLedger
    tracker: ChangeTracker
    tokens: TokenService
    persons: PersonService
    organizations: OrganizationService
    dossiers: DossierService
    catalogue: MedicationCatalogue
    medications: MedicationService
    consents: ConsentService
    access: AccessService
    auth: AuthService
    offline: OfflineBundleService
    sync: OfflineSyncService
    email: EmailSender
    identity_provider: IdentityProvider


def build_container(settings: Settings | None = None) -> Container:
    settings = settings or get_settings()
    keyring = settings.keyring()

    identity = IdentityService(keyring, store_sealed_ahvn=settings.store_sealed_ahvn)
    ledger = AuditLedger(keyring)
    tracker = ChangeTracker(ledger)
    tokens = TokenService(
        keyring,
        issuer=settings.issuer,
        audience=settings.service_name,
        clock_skew_seconds=settings.clock_skew_seconds,
        max_ttl_seconds=settings.max_token_ttl_seconds,
    )

    email: EmailSender = (
        SmtpEmailSender(settings.smtp_host, settings.smtp_port, settings.smtp_from)
        if settings.smtp_host
        else InMemoryEmailSender()
    )
    if settings.environment is Environment.PRODUCTION and isinstance(
        email, InMemoryEmailSender
    ):  # pragma: no cover - guarded again by Settings validation
        raise RuntimeError("production requires a real SMTP sender")

    provider: IdentityProvider = (
        MockIdentityProvider(production=settings.environment is Environment.PRODUCTION)
        if settings.use_mock_idp
        else SwissIdClient(
            OidcConfig(
                issuer=settings.swissid_issuer,
                client_id=settings.swissid_client_id,
                client_secret=settings.swissid_client_secret,
                redirect_uri=settings.swissid_redirect_uri,
                scopes=tuple(settings.swissid_scopes),
            )
        )
    )

    persons = PersonService(identity, ledger, tracker)
    consents = ConsentService(ledger, tracker, persons)
    medications = MedicationService(ledger, tracker, persons)
    return Container(
        settings=settings,
        keyring=keyring,
        identity=identity,
        ledger=ledger,
        tracker=tracker,
        tokens=tokens,
        persons=persons,
        organizations=OrganizationService(ledger, tracker),
        dossiers=DossierService(
            ledger, tracker, persons, retention_years=settings.dossier_retention_years
        ),
        catalogue=MedicationCatalogue(ledger, tracker),
        # The medication service asks the person registry whether the author
        # holds a live practice licence before accepting a prescription.
        medications=medications,
        consents=consents,
        access=AccessService(
            tokens,
            consents,
            ledger,
            tracker,
            persons,
            capability_ttl_seconds=settings.capability_token_ttl_seconds,
            visitor_ttl_seconds=settings.visitor_token_ttl_seconds,
            emergency_ttl_seconds=settings.emergency_token_ttl_seconds,
        ),
        auth=AuthService(
            provider=provider,
            tokens=tokens,
            otp=OtpService(
                keyring,
                email,
                code_length=settings.otp_length,
                ttl_seconds=settings.otp_ttl_seconds,
            ),
            identity=identity,
            keyring=keyring,
            ledger=ledger,
            persons=persons,
            session_ttl_seconds=settings.session_token_ttl_seconds,
            refresh_ttl_seconds=settings.refresh_token_ttl_seconds,
            otp_max_attempts=settings.otp_max_attempts,
            max_failed_logins=settings.login_max_attempts_per_hour,
        ),
        offline=OfflineBundleService(keyring, ledger, issuer=settings.issuer),
        sync=OfflineSyncService(medications, ledger),
        email=email,
        identity_provider=provider,
    )


@lru_cache
def get_container() -> Container:
    return build_container()
