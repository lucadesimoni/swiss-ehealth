# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Shared fixtures.

Each test gets its own file-backed SQLite database and its own keyring, so
tests cannot leak state into each other through either.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from ehealth.config import Environment, Settings
from ehealth.container import Container, build_container
from ehealth.db import create_all, get_session_factory, init_engine
from ehealth.domain.uid import Ahvn13
from ehealth.main import create_app
from ehealth.models.core import PersonKind
from ehealth.security.mfa import InMemoryEmailSender
from ehealth.security.oidc import MockIdentityProvider
from ehealth.services.audit import ActorContext
from ehealth.services.persons import PersonRegistration

ADMIN_KEY = "test-admin-key-that-is-long-enough-32ch"

#: Valid AHVN13s (correct EAN-13 check digit) used across the suite.
AHVN_ANNA = "756.1234.5678.97"
AHVN_BEAT = "756.9217.0769.85"
AHVN_CARLA = "756.3047.5009.62"
AHVN_DORA = "756.1111.1111.13"


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        environment=Environment.LOCAL,
        database_url=f"sqlite+pysqlite:///{tmp_path / 'test.db'}",
        issuer="https://test.dossier.ch",
        service_name="ch.ehealth.test",
        admin_api_key=ADMIN_KEY,
        use_mock_idp=True,
        smtp_host="",
        otp_ttl_seconds=300,
        capability_token_ttl_seconds=600,
    )


@pytest.fixture
def container(settings: Settings) -> Container:
    init_engine(settings)
    create_all()
    return build_container(settings)


@pytest.fixture
def db(container: Container) -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    finally:
        session.close()


@pytest.fixture
def client(settings: Settings, container: Container) -> Iterator[TestClient]:
    app = create_app(settings, container=container)
    with TestClient(app) as test_client:
        test_client.headers.update({"X-Admin-Key": ADMIN_KEY})
        yield test_client


@pytest.fixture
def system_actor() -> ActorContext:
    return ActorContext.system(request_id="test")


@pytest.fixture
def mock_idp(container: Container) -> MockIdentityProvider:
    provider = container.identity_provider
    assert isinstance(provider, MockIdentityProvider)
    return provider


@pytest.fixture
def outbox(container: Container) -> InMemoryEmailSender:
    sender = container.email
    assert isinstance(sender, InMemoryEmailSender)
    return sender


# --------------------------------------------------------------------------
# Domain helpers
# --------------------------------------------------------------------------


@dataclass
class World:
    """A minimal but realistic starting position for service-level tests."""

    organization: object
    patient: object
    doctor: object
    visitor: object
    dossier: object
    consent: object


@pytest.fixture
def world(container: Container, db: Session, system_actor: ActorContext) -> World:
    organization = container.organizations.register(
        db, system_actor, name="Universitätsspital Test", che_uid="CHE-109.322.551"
    )
    patient = container.persons.register(
        db,
        PersonRegistration(
            kind=PersonKind.PATIENT,
            given_name="Anna",
            family_name="Muster",
            ahvn13=AHVN_ANNA,
            email="anna.muster@example.ch",
        ),
        system_actor,
    )
    doctor = container.persons.register(
        db,
        PersonRegistration(
            kind=PersonKind.HEALTHCARE_PROFESSIONAL,
            given_name="Beat",
            family_name="Arzt",
            ahvn13=AHVN_BEAT,
            gln="7601000000002",
            profession="Facharzt Innere Medizin",
            organization_uid=organization.uid,
        ),
        system_actor,
    )
    visitor = container.persons.register(
        db,
        PersonRegistration(
            kind=PersonKind.VISITOR,
            given_name="Carla",
            family_name="Besuch",
            ahvn13=AHVN_CARLA,
        ),
        system_actor,
    )
    dossier = container.dossiers.open(db, system_actor, patient=patient)
    consent = container.consents.record(db, system_actor, patient=patient)
    db.commit()
    return World(
        organization=organization,
        patient=patient,
        doctor=doctor,
        visitor=visitor,
        dossier=dossier,
        consent=consent,
    )


def valid_ahvn(value: str) -> Ahvn13:
    return Ahvn13.parse(value)


def gln(value: str) -> str:
    return value


@dataclass
class LoggedIn:
    person_uid: str
    access_token: str
    refresh_token: str
    session_uid: str

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}


def login(
    client: TestClient,
    mock_idp: MockIdentityProvider,
    outbox: InMemoryEmailSender,
    *,
    person_uid: str,
    subject: str,
    email: str,
) -> LoggedIn:
    """Run the full SwissID + email OTP flow over HTTP."""
    mock_idp.enrol(subject, email=email)
    linked = client.post(
        "/auth/accounts/link",
        json={
            "person_uid": person_uid,
            "issuer": "https://mock-idp.local",
            "subject": subject,
            "email": email,
        },
    )
    assert linked.status_code == 201, linked.text

    started = client.post("/auth/login")
    assert started.status_code == 200, started.text
    state = started.json()["state"]

    # The mock provider stands in for the user authenticating at SwissID.
    from ehealth.models.auth import OidcFlow
    from sqlalchemy import select

    from ehealth.db import get_session_factory

    with get_session_factory()() as session:
        flow = session.execute(
            select(OidcFlow).where(OidcFlow.state == state)
        ).scalars().one()
        nonce = flow.nonce
    code = mock_idp.authorize(subject, nonce)

    challenge = client.post("/auth/callback", json={"state": state, "code": code})
    assert challenge.status_code == 200, challenge.text
    session_uid = challenge.json()["session_uid"]

    otp = outbox.last_code_for(email)
    assert otp is not None
    verified = client.post(
        "/auth/mfa/verify", json={"session_uid": session_uid, "code": otp}
    )
    assert verified.status_code == 200, verified.text
    body = verified.json()
    return LoggedIn(
        person_uid=body["person_uid"],
        access_token=body["access_token"],
        refresh_token=body["refresh_token"],
        session_uid=body["session_uid"],
    )
