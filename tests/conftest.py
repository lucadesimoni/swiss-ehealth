# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Shared fixtures.

Each test gets its own database and its own keyring, so tests cannot leak
state into each other through either.

By default that database is a file-backed SQLite one, which is fast and needs
nothing installed. Set ``EHEALTH_TEST_DATABASE_URL`` to a PostgreSQL URL and
the whole suite runs against PostgreSQL instead, one schema per test — see
:func:`postgres_schema`. Production runs on PostgreSQL, and a suite that only
ever exercises SQLite cannot see a JSONB mismatch, a stricter transactional
rule, or a reserved word until a deployment does.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from ehealth.config import Environment, Settings
from ehealth.container import Container, build_container
from ehealth.db import create_all, get_session_factory, init_engine
from ehealth.domain.uid import Ahvn13
from ehealth.main import create_app
from ehealth.models.core import (
    MedicalProfession,
    PersonRoleKind,
    ProfessionalRegister,
)
from ehealth.security.mfa import InMemoryEmailSender
from ehealth.security.oidc import MockIdentityProvider
from ehealth.services.audit import ActorContext
from ehealth.services.persons import CredentialRegistration, PersonRegistration

ADMIN_KEY = "test-admin-key-that-is-long-enough-32ch"

#: Point the suite at PostgreSQL, e.g.
#: ``postgresql+psycopg://ehealth@localhost:5432/ehealth_test``.
TEST_DATABASE_URL_ENV = "EHEALTH_TEST_DATABASE_URL"

#: Valid AHVN13s (correct EAN-13 check digit) used across the suite.
AHVN_ANNA = "756.1234.5678.97"
AHVN_BEAT = "756.9217.0769.85"
AHVN_CARLA = "756.3047.5009.62"
AHVN_DORA = "756.1111.1111.13"


def postgres_url() -> str | None:
    """The PostgreSQL URL the suite was asked to use, if any."""
    url = os.environ.get(TEST_DATABASE_URL_ENV, "").strip()
    return url or None


@pytest.fixture
def database_url(tmp_path) -> Iterator[str]:
    """A private database for one test.

    On SQLite that is a file in the test's own ``tmp_path``. On PostgreSQL it
    is a schema created for this test and dropped afterwards: one database
    with a schema per test is dramatically faster than a database per test,
    and isolates just as well, because ``search_path`` makes the schema
    invisible to everything else.
    """
    configured = postgres_url()
    if configured is None:
        yield f"sqlite+pysqlite:///{tmp_path / 'test.db'}"
        return

    schema = f"t_{uuid.uuid4().hex[:16]}"
    admin = create_engine(configured, poolclass=None)
    with admin.begin() as connection:
        connection.execute(text(f'create schema "{schema}"'))

    # -c search_path is what makes every unqualified table land in this
    # test's schema without a single model needing to know about it.
    scoped = make_url(configured).update_query_dict(
        {"options": f"-csearch_path={schema}"}, append=True
    )
    try:
        yield scoped.render_as_string(hide_password=False)
    finally:
        # A leaked schema would slowly turn the test database into a landfill,
        # so the drop runs even when the test failed.
        with admin.begin() as connection:
            connection.execute(text(f'drop schema if exists "{schema}" cascade'))
        admin.dispose()


@pytest.fixture
def settings(database_url: str) -> Settings:
    return Settings(
        environment=Environment.LOCAL,
        database_url=database_url,
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
    credential: object
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
            roles=[PersonRoleKind.PATIENT],
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
            # Beat is a physician *and* a patient: one person, one UID, one
            # pseudonym, two roles. This is the case the single-kind model
            # could not represent.
            roles=[PersonRoleKind.PATIENT],
            given_name="Beat",
            family_name="Arzt",
            ahvn13=AHVN_BEAT,
        ),
        system_actor,
    )
    credential = container.persons.register_credential(
        db,
        doctor,
        system_actor,
        CredentialRegistration(
            gln="7601000000002",
            register=ProfessionalRegister.MEDREG,
            profession=MedicalProfession.PHYSICIAN,
            specialisation="Facharzt Allgemeine Innere Medizin",
            licence_canton="ZH",
            licence_number="ZH-2019-04412",
            organization_uid=organization.uid,
        ),
    )
    visitor = container.persons.register(
        db,
        PersonRegistration(
            roles=[PersonRoleKind.VISITOR],
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
        credential=credential,
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
        "/v1/auth/accounts/link",
        json={
            "person_uid": person_uid,
            "issuer": "https://mock-idp.local",
            "subject": subject,
            "email": email,
        },
    )
    assert linked.status_code == 201, linked.text

    started = client.post("/v1/auth/login")
    assert started.status_code == 200, started.text
    state = started.json()["state"]

    # The mock provider stands in for the user authenticating at SwissID.
    from sqlalchemy import select

    from ehealth.db import get_session_factory
    from ehealth.models.auth import OidcFlow

    with get_session_factory()() as session:
        flow = (
            session.execute(select(OidcFlow).where(OidcFlow.state == state))
            .scalars()
            .one()
        )
        nonce = flow.nonce
    code = mock_idp.authorize(subject, nonce)

    challenge = client.post("/v1/auth/callback", json={"state": state, "code": code})
    assert challenge.status_code == 200, challenge.text
    session_uid = challenge.json()["session_uid"]

    otp = outbox.last_code_for(email)
    assert otp is not None
    verified = client.post(
        "/v1/auth/mfa/verify", json={"session_uid": session_uid, "code": otp}
    )
    assert verified.status_code == 200, verified.text
    body = verified.json()
    return LoggedIn(
        person_uid=body["person_uid"],
        access_token=body["access_token"],
        refresh_token=body["refresh_token"],
        session_uid=body["session_uid"],
    )


@pytest.fixture
def registry(client):
    """Enrolment-side setup, done with the admin key."""
    organization = client.post(
        "/v1/organizations",
        json={"name": "Kantonsspital Test", "che_uid": "CHE-109.322.551"},
    )
    assert organization.status_code == 201, organization.text
    org_uid = organization.json()["uid"]

    patient = client.post(
        "/v1/persons",
        json={
            "roles": ["patient"],
            "given_name": "Anna",
            "family_name": "Muster",
            "ahvn13": AHVN_ANNA,
            "birth_date": "1985-04-12",
            "email": "anna.muster@example.ch",
        },
    )
    assert patient.status_code == 201, patient.text

    doctor = client.post(
        "/v1/persons",
        json={
            # Beat is registered as a patient too — one person, two roles.
            "roles": ["patient"],
            "given_name": "Beat",
            "family_name": "Arzt",
            "ahvn13": AHVN_BEAT,
        },
    )
    assert doctor.status_code == 201, doctor.text
    credential = client.post(
        f"/v1/persons/{doctor.json()['uid']}/credentials",
        json={
            "gln": "7601000000002",
            "professional_register": "medreg",
            "profession": "physician",
            "specialisation": "Facharzt Allgemeine Innere Medizin",
            "licence_canton": "ZH",
            "licence_number": "ZH-2019-04412",
            "zsr_number": "A123456",
            "organization_uid": org_uid,
        },
    )
    assert credential.status_code == 201, credential.text
    verified = client.post(
        f"/v1/credentials/{credential.json()['uid']}/verify",
        json={"source": "MedReg", "evidence": {"checked": "e2e"}},
    )
    assert verified.status_code == 200, verified.text

    visitor = client.post(
        "/v1/persons",
        json={
            "roles": ["visitor"],
            "given_name": "Carla",
            "family_name": "Besuch",
            "ahvn13": AHVN_CARLA,
        },
    )
    assert visitor.status_code == 201, visitor.text

    dossier = client.post("/v1/dossiers", json={"patient_uid": patient.json()["uid"]})
    assert dossier.status_code == 201, dossier.text

    product = client.post(
        "/v1/products",
        json={
            "gtin": "7601000000002",
            "name": "Lisinopril Test 10mg",
            "atc_code": "C09AA03",
            "active_ingredient": "Lisinopril",
            "strength": "10 mg",
            "swissmedic_authorisation": "62536",
            "pharmacode": "1234567",
            "dispensing_category": "B",
            "sl_listed": True,
        },
    )
    assert product.status_code == 201, product.text

    return {
        "org": org_uid,
        "patient": patient.json(),
        "doctor": doctor.json(),
        "visitor": visitor.json(),
        "credential": verified.json(),
        "dossier": dossier.json(),
        "product": product.json(),
    }


# -- logged-in people, for the document and FHIR tests ---------------------------


@pytest.fixture
def patient(client, mock_idp, outbox, world):
    return login(
        client,
        mock_idp,
        outbox,
        person_uid=world.patient.uid,
        subject="anna-swissid",
        email="anna.muster@example.ch",
    )


@pytest.fixture
def doctor(client, mock_idp, outbox, world):
    return login(
        client,
        mock_idp,
        outbox,
        person_uid=world.doctor.uid,
        subject="beat-swissid",
        email="beat.arzt@example.ch",
    )


@pytest.fixture
def headers(client, patient, doctor, world):
    """A doctor the patient has designated for RESTRICTED material (EPDV
    annex 2): the grant alone cannot raise the level, the consent rule does."""
    rule = client.post(
        "/v1/consent/rules",
        headers=patient.auth_header,
        json={
            "subject_type": "person",
            "subject_uid": world.doctor.uid,
            "effect": "allow",
            "access_level": "restricted",
        },
    )
    assert rule.status_code == 201, rule.text
    from tests.document_helpers import capability

    return capability(client, patient, doctor, world, level="restricted")
