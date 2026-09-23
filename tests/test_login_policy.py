# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Level of assurance, provider-asserted second factor, and several providers.

The deployment configured here is the shape a real one takes:

* SwissID accepts ``loa-2`` and ``loa-3``; ``loa-3`` already proves two
  factors, so it completes the login; healthcare professionals need ``loa-3``.
* HIN — the professionals' provider — accepts only ``hin-2fa``, which is two
  factors by definition.

The level names are placeholders for whatever vocabulary each provider
actually uses; the rules are what is under test.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ehealth.config import Environment, IdentityProviderSettings, Settings
from ehealth.db import get_session_factory
from ehealth.models.audit import AuditAction, AuditEvent
from ehealth.models.auth import AuthSession, OidcFlow, SessionState
from tests.conftest import ADMIN_KEY

SWISSID_ISSUER = "https://mock-idp.local"
HIN_ISSUER = "https://mock-hin.local"
EMAIL = "anna.muster@example.ch"


@pytest.fixture
def settings(database_url) -> Settings:
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
        swissid_accepted_acr=("loa-2", "loa-3"),
        swissid_mfa_acr=("loa-3",),
        swissid_professional_acr=("loa-3",),
        extra_identity_providers=(
            IdentityProviderSettings(
                name="hin",
                issuer="https://oidc.hin.ch",
                accepted_acr=("hin-2fa",),
                mfa_acr=("hin-2fa",),
            ),
        ),
    )


def link(client, *, person_uid, issuer=SWISSID_ISSUER, subject, email=EMAIL):
    return client.post(
        "/v1/auth/accounts/link",
        json={
            "person_uid": person_uid,
            "issuer": issuer,
            "subject": subject,
            "email": email,
        },
    )


def callback(client, container, *, provider="swissid", subject, acr, email=EMAIL):
    """Start at ``provider``, have the user authenticate at ``acr``, return
    the callback response."""
    idp = container.identity_providers[provider]
    idp.enrol(subject, email=email, acr=acr)
    started = client.post("/v1/auth/login", params={"provider": provider})
    assert started.status_code == 200, started.text
    state = started.json()["state"]
    with get_session_factory()() as db:
        flow = (
            db.execute(select(OidcFlow).where(OidcFlow.state == state)).scalars().one()
        )
        assert flow.provider == provider
        nonce = flow.nonce
    code = idp.authorize(subject, nonce)
    return client.post("/v1/auth/callback", json={"state": state, "code": code})


def audit_events(action: AuditAction) -> list[AuditEvent]:
    with get_session_factory()() as db:
        return list(
            db.execute(select(AuditEvent).where(AuditEvent.action == action.value))
            .scalars()
            .all()
        )


def sessions() -> list[AuthSession]:
    with get_session_factory()() as db:
        return list(db.execute(select(AuthSession)).scalars().all())


class TestLevelOfAssurance:
    def test_a_level_below_the_minimum_is_refused(self, client, container, world):
        """Requesting a level is not enough: the provider may answer with
        less, and the answer is what counts."""
        link(client, person_uid=world.patient.uid, subject="anna")
        response = callback(client, container, subject="anna", acr="loa-1")
        assert response.status_code == 401
        assert not sessions(), "a refused login must not leave a session behind"
        (failure,) = audit_events(AuditAction.LOGIN_FAILED)
        assert "below the accepted minimum" in failure.detail["reason"]

    def test_a_token_without_any_level_is_refused(self, client, container, world):
        link(client, person_uid=world.patient.uid, subject="anna")
        assert callback(client, container, subject="anna", acr=None).status_code == 401

    def test_the_refusal_does_not_reveal_whether_the_identity_is_enrolled(
        self, client, container, world
    ):
        """Assurance is checked before the account lookup, so an unenrolled
        identity and an enrolled one at too low a level fail identically."""
        link(client, person_uid=world.patient.uid, subject="anna")
        enrolled = callback(client, container, subject="anna", acr="loa-1")
        stranger = callback(client, container, subject="stranger", acr="loa-1")
        assert enrolled.status_code == stranger.status_code == 401
        assert enrolled.json() == stranger.json()


class TestProviderAssertedSecondFactor:
    def test_a_two_factor_level_completes_the_login(
        self, client, container, world, outbox
    ):
        link(client, person_uid=world.patient.uid, subject="anna")
        response = callback(client, container, subject="anna", acr="loa-3")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["second_factor"] == "idp"
        assert body["session"]["access_token"]
        assert outbox.last_code_for(EMAIL) is None, "no email code may be sent"

        (auth_session,) = sessions()
        assert auth_session.state == SessionState.ACTIVE.value
        assert auth_session.assurance_level == "aal2"
        assert auth_session.auth_methods == ["swissid", "idp-mfa"]

        (success,) = audit_events(AuditAction.MFA_SUCCEEDED)
        assert success.detail["method"] == "idp-mfa"
        assert success.detail["idp_acr"] == "loa-3"

    def test_the_session_it_yields_is_a_working_session(self, client, container, world):
        link(client, person_uid=world.patient.uid, subject="anna")
        body = callback(client, container, subject="anna", acr="loa-3").json()
        with get_session_factory()() as db:
            claims, _ = container.auth.verify_session_token(
                db, body["session"]["access_token"]
            )
        assert claims.subject_uid == world.patient.uid

    def test_below_it_the_email_code_is_still_the_second_factor(
        self, client, container, world, outbox
    ):
        link(client, person_uid=world.patient.uid, subject="anna")
        response = callback(client, container, subject="anna", acr="loa-2")
        body = response.json()
        assert body["second_factor"] == "otp-email"
        assert body["session"] is None

        code = outbox.last_code_for(EMAIL)
        verified = client.post(
            "/v1/auth/mfa/verify",
            json={"session_uid": body["session_uid"], "code": code},
        )
        assert verified.status_code == 200, verified.text
        (auth_session,) = sessions()
        assert auth_session.auth_methods == ["swissid", "otp-email"]


class TestProfessionals:
    """A professional's session reaches other people's records, so the floor
    is higher for them than for a patient reading their own."""

    def test_a_professional_below_the_professional_level_is_refused(
        self, client, container, world
    ):
        link(client, person_uid=world.doctor.uid, subject="beat")
        response = callback(client, container, subject="beat", acr="loa-2")
        assert response.status_code == 401
        (failure,) = audit_events(AuditAction.LOGIN_FAILED)
        assert "healthcare professionals" in failure.detail["reason"]

    def test_the_same_level_is_fine_for_a_patient(self, client, container, world):
        link(client, person_uid=world.patient.uid, subject="anna")
        assert (
            callback(client, container, subject="anna", acr="loa-2").status_code == 200
        )

    def test_a_professional_at_the_professional_level_gets_in(
        self, client, container, world
    ):
        link(client, person_uid=world.doctor.uid, subject="beat")
        response = callback(client, container, subject="beat", acr="loa-3")
        assert response.status_code == 200
        assert response.json()["second_factor"] == "idp"


class TestSeveralProviders:
    def test_the_providers_are_listed_by_name_only(self, client):
        body = client.get("/v1/auth/providers").json()
        assert body == {"providers": ["swissid", "hin"], "default": "swissid"}

    def test_an_unknown_provider_is_refused(self, client):
        response = client.post("/v1/auth/login", params={"provider": "facebook"})
        assert response.status_code == 400

    def test_a_professional_can_hold_a_hin_and_a_swissid_identity(
        self, client, container, world
    ):
        """One person, two ways in: HIN at the practice, SwissID as a
        patient. Both resolve to the same person."""
        assert (
            link(client, person_uid=world.doctor.uid, subject="beat").status_code == 201
        )
        assert (
            link(
                client,
                person_uid=world.doctor.uid,
                issuer=HIN_ISSUER,
                subject="beat-hin",
            ).status_code
            == 201
        )
        hin = callback(
            client, container, provider="hin", subject="beat-hin", acr="hin-2fa"
        )
        assert hin.status_code == 200, hin.text
        assert hin.json()["session"]["person_uid"] == world.doctor.uid
        (auth_session,) = sessions()
        assert auth_session.auth_methods == ["hin", "idp-mfa"]

    def test_two_identities_at_one_provider_are_refused(self, client, world):
        """That would be two ways in that the audit trail cannot tell apart."""
        assert (
            link(client, person_uid=world.patient.uid, subject="anna").status_code
            == 201
        )
        second = link(client, person_uid=world.patient.uid, subject="anna-2")
        assert second.status_code == 409

    def test_levels_are_each_providers_own_vocabulary(self, client, container, world):
        """``loa-3`` means something at SwissID and nothing at HIN."""
        link(client, person_uid=world.doctor.uid, issuer=HIN_ISSUER, subject="beat-hin")
        response = callback(
            client, container, provider="hin", subject="beat-hin", acr="loa-3"
        )
        assert response.status_code == 401

    def test_an_identity_from_one_provider_is_useless_at_another(
        self, client, container, world
    ):
        """Accounts are keyed by issuer *and* subject: the same subject string
        arriving from a different provider is a different person."""
        link(client, person_uid=world.patient.uid, subject="shared-subject")
        response = callback(
            client, container, provider="hin", subject="shared-subject", acr="hin-2fa"
        )
        assert response.status_code == 401

    def test_a_flow_is_finished_by_the_provider_that_began_it(
        self, client, container, world
    ):
        """If configuration changed between start and callback, the flow is
        refused — never completed by whichever provider is configured now."""
        link(client, person_uid=world.patient.uid, subject="anna")
        idp = container.identity_providers["swissid"]
        idp.enrol("anna", email=EMAIL, acr="loa-3")
        state = client.post("/v1/auth/login").json()["state"]
        with get_session_factory()() as db:
            flow = (
                db.execute(select(OidcFlow).where(OidcFlow.state == state))
                .scalars()
                .one()
            )
            nonce = flow.nonce
            flow.provider = "retired-provider"
            db.commit()
        code = idp.authorize("anna", nonce)
        response = client.post("/v1/auth/callback", json={"state": state, "code": code})
        assert response.status_code == 401

    def test_client_jwks_is_empty_while_providers_use_secrets(self, client):
        assert client.get("/v1/auth/jwks.json").json() == {"keys": []}
