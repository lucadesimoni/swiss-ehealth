# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""SwissID + email OTP login, session lifecycle and refresh rotation."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from ehealth.models.audit import AuditEvent
from ehealth.models.auth import AuthSession, OidcFlow, OtpChallenge, SessionState
from ehealth.models.governance import IssuedToken
from ehealth.services.auth import mask_email

from tests.conftest import login

EMAIL = "anna.muster@example.ch"
SUBJECT = "swissid-subject-anna"


def start_and_callback(client, mock_idp, *, subject=SUBJECT):
    started = client.post("/v1/auth/login")
    state = started.json()["state"]
    from ehealth.db import get_session_factory

    with get_session_factory()() as session:
        flow = session.execute(
            select(OidcFlow).where(OidcFlow.state == state)
        ).scalars().one()
        nonce = flow.nonce
    code = mock_idp.authorize(subject, nonce)
    return state, code


class TestMaskEmail:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("anna.muster@example.ch", "a***r@example.ch"),
            ("ab@example.ch", "a***@example.ch"),
            ("no-at-sign", "***"),
        ],
    )
    def test_masks(self, address, expected):
        assert mask_email(address) == expected


class TestHappyPath:
    def test_full_login_reaches_aal2(self, client, mock_idp, outbox, world):
        session = login(
            client,
            mock_idp,
            outbox,
            person_uid=world.patient.uid,
            subject=SUBJECT,
            email=EMAIL,
        )
        assert session.access_token and session.refresh_token
        assert session.person_uid == world.patient.uid

        from ehealth.db import get_session_factory

        with get_session_factory()() as db:
            auth_session = db.get(AuthSession, session.session_uid)
            assert auth_session.state == SessionState.ACTIVE.value
            assert auth_session.assurance_level == "aal2"
            assert auth_session.auth_methods == ["swissid", "otp-email"]

    def test_the_code_is_emailed_and_never_returned(
        self, client, mock_idp, outbox, world
    ):
        client.post(
            "/v1/auth/accounts/link",
            json={
                "person_uid": world.patient.uid,
                "issuer": "https://mock-idp.local",
                "subject": SUBJECT,
                "email": EMAIL,
            },
        )
        mock_idp.enrol(SUBJECT, email=EMAIL)
        state, code = start_and_callback(client, mock_idp)
        response = client.post("/v1/auth/callback", json={"state": state, "code": code})
        body = response.json()
        assert body["masked_email"] == "a***r@example.ch"
        assert EMAIL not in response.text
        otp = outbox.last_code_for(EMAIL)
        assert otp and otp not in response.text

    def test_only_a_hash_of_the_code_is_stored(self, client, mock_idp, outbox, world):
        client.post(
            "/v1/auth/accounts/link",
            json={
                "person_uid": world.patient.uid,
                "issuer": "https://mock-idp.local",
                "subject": SUBJECT,
                "email": EMAIL,
            },
        )
        mock_idp.enrol(SUBJECT, email=EMAIL)
        state, code = start_and_callback(client, mock_idp)
        client.post("/v1/auth/callback", json={"state": state, "code": code})
        otp = outbox.last_code_for(EMAIL)

        from ehealth.db import get_session_factory

        with get_session_factory()() as db:
            challenge = db.execute(select(OtpChallenge)).scalars().one()
            assert otp not in challenge.code_hash


class TestSecondFactorIsMandatory:
    @pytest.fixture
    def pending(self, client, mock_idp, outbox, world):
        client.post(
            "/v1/auth/accounts/link",
            json={
                "person_uid": world.patient.uid,
                "issuer": "https://mock-idp.local",
                "subject": SUBJECT,
                "email": EMAIL,
            },
        )
        mock_idp.enrol(SUBJECT, email=EMAIL)
        state, code = start_and_callback(client, mock_idp)
        response = client.post("/v1/auth/callback", json={"state": state, "code": code})
        return response.json()["session_uid"]

    def test_a_pending_session_carries_no_authority(self, client, pending):
        """SwissID alone must not open the record."""
        from ehealth.db import get_session_factory

        with get_session_factory()() as db:
            assert (
                db.get(AuthSession, pending).state == SessionState.PENDING_MFA.value
            )
            tokens = db.execute(select(IssuedToken)).scalars().all()
            assert tokens == []

    def test_a_wrong_code_is_refused(self, client, pending):
        response = client.post(
            "/v1/auth/mfa/verify", json={"session_uid": pending, "code": "000000"}
        )
        assert response.status_code == 401

    def test_attempts_are_capped(self, client, pending, container):
        for _ in range(container.settings.otp_max_attempts):
            client.post(
                "/v1/auth/mfa/verify", json={"session_uid": pending, "code": "000000"}
            )
        # Even the right code no longer works once the cap is hit.
        response = client.post(
            "/v1/auth/mfa/verify", json={"session_uid": pending, "code": "000001"}
        )
        assert response.status_code == 401

        from ehealth.db import get_session_factory

        with get_session_factory()() as db:
            assert db.get(AuthSession, pending).state == SessionState.REVOKED.value

    def test_a_code_is_single_use(self, client, pending, outbox):
        otp = outbox.last_code_for(EMAIL)
        first = client.post(
            "/v1/auth/mfa/verify", json={"session_uid": pending, "code": otp}
        )
        assert first.status_code == 200
        second = client.post(
            "/v1/auth/mfa/verify", json={"session_uid": pending, "code": otp}
        )
        assert second.status_code == 401

    def test_resend_invalidates_the_previous_code(self, client, pending, outbox):
        old_code = outbox.last_code_for(EMAIL)
        resent = client.post("/v1/auth/mfa/resend", json={"session_uid": pending})
        assert resent.status_code == 200
        new_code = outbox.last_code_for(EMAIL)
        assert new_code != old_code

        stale = client.post(
            "/v1/auth/mfa/verify", json={"session_uid": pending, "code": old_code}
        )
        assert stale.status_code == 401
        fresh = client.post(
            "/v1/auth/mfa/verify", json={"session_uid": pending, "code": new_code}
        )
        assert fresh.status_code == 200


class TestFlowIntegrity:
    def test_an_unknown_state_is_refused(self, client, mock_idp, world):
        response = client.post(
            "/v1/auth/callback", json={"state": "made-up", "code": "whatever"}
        )
        assert response.status_code == 401

    def test_a_callback_cannot_be_replayed(self, client, mock_idp, outbox, world):
        client.post(
            "/v1/auth/accounts/link",
            json={
                "person_uid": world.patient.uid,
                "issuer": "https://mock-idp.local",
                "subject": SUBJECT,
                "email": EMAIL,
            },
        )
        mock_idp.enrol(SUBJECT, email=EMAIL)
        state, code = start_and_callback(client, mock_idp)
        assert client.post("/v1/auth/callback", json={"state": state, "code": code}).status_code == 200
        replay = client.post("/v1/auth/callback", json={"state": state, "code": code})
        assert replay.status_code == 401

    def test_an_unlinked_identity_gets_nothing(self, client, mock_idp, world):
        """A valid SwissID this system has never heard of must not
        auto-provision itself a health record account."""
        mock_idp.enrol("stranger", email="stranger@example.ch")
        state, code = start_and_callback(client, mock_idp, subject="stranger")
        response = client.post("/v1/auth/callback", json={"state": state, "code": code})
        assert response.status_code == 401
        assert "stranger" not in response.text

    def test_failures_are_indistinguishable_from_each_other(
        self, client, mock_idp, world
    ):
        unknown_state = client.post(
            "/v1/auth/callback", json={"state": "nope", "code": "x"}
        )
        mock_idp.enrol("stranger2", email="s2@example.ch")
        state, code = start_and_callback(client, mock_idp, subject="stranger2")
        unlinked = client.post("/v1/auth/callback", json={"state": state, "code": code})
        assert unknown_state.json() == unlinked.json()

    def test_every_attempt_is_audited(self, client, mock_idp, world):
        client.post("/v1/auth/callback", json={"state": "nope", "code": "x"})
        from ehealth.db import get_session_factory

        with get_session_factory()() as db:
            failures = db.execute(
                select(AuditEvent).where(AuditEvent.action == "auth.login_failed")
            ).scalars().all()
            assert len(failures) == 1
            assert failures[0].outcome == "denied"


class TestEnrolment:
    def test_requires_the_admin_key(self, client, world):
        response = client.post(
            "/v1/auth/accounts/link",
            headers={"X-Admin-Key": "wrong"},
            json={
                "person_uid": world.patient.uid,
                "issuer": "https://mock-idp.local",
                "subject": "x",
                "email": EMAIL,
            },
        )
        assert response.status_code == 401

    def test_refuses_to_link_the_same_identity_twice(self, client, world):
        payload = {
            "person_uid": world.patient.uid,
            "issuer": "https://mock-idp.local",
            "subject": SUBJECT,
            "email": EMAIL,
        }
        assert client.post("/v1/auth/accounts/link", json=payload).status_code == 201
        assert client.post("/v1/auth/accounts/link", json=payload).status_code == 409


class TestSessionLifecycle:
    @pytest.fixture
    def session(self, client, mock_idp, outbox, world):
        return login(
            client,
            mock_idp,
            outbox,
            person_uid=world.patient.uid,
            subject=SUBJECT,
            email=EMAIL,
        )

    def test_the_access_token_opens_the_api(self, client, session):
        response = client.get("/v1/persons/me", headers=session.auth_header)
        assert response.status_code == 200
        assert response.json()["uid"] == session.person_uid

    def test_an_unauthenticated_call_is_refused(self, client):
        assert client.get("/v1/persons/me").status_code == 401

    def test_a_garbage_token_is_refused(self, client):
        response = client.get(
            "/v1/persons/me", headers={"Authorization": "Bearer nonsense"}
        )
        assert response.status_code == 401

    def test_refresh_rotates_both_tokens(self, client, session):
        response = client.post(
            "/v1/auth/refresh", json={"refresh_token": session.refresh_token}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["refresh_token"] != session.refresh_token
        assert body["access_token"] != session.access_token

    def test_the_old_access_token_dies_on_rotation(self, client, session):
        """A refresh must not leave a second live credential behind."""
        client.post("/v1/auth/refresh", json={"refresh_token": session.refresh_token})
        stale = client.get("/v1/persons/me", headers=session.auth_header)
        assert stale.status_code == 401

    def test_replaying_a_refresh_token_destroys_the_session(self, client, session):
        """Reuse of a rotated token is the signature of theft, so the whole
        family dies rather than the request merely failing."""
        rotated = client.post(
            "/v1/auth/refresh", json={"refresh_token": session.refresh_token}
        ).json()
        replay = client.post(
            "/v1/auth/refresh", json={"refresh_token": session.refresh_token}
        )
        assert replay.status_code == 401

        # The tokens issued by the legitimate rotation are dead too.
        after = client.get(
            "/v1/persons/me", headers={"Authorization": f"Bearer {rotated['access_token']}"}
        )
        assert after.status_code == 401

    def test_logout_revokes_everything(self, client, session):
        assert client.post("/v1/auth/logout", headers=session.auth_header).status_code == 204
        assert client.get("/v1/persons/me", headers=session.auth_header).status_code == 401
        assert (
            client.post(
                "/v1/auth/refresh", json={"refresh_token": session.refresh_token}
            ).status_code
            == 401
        )

    def test_a_refresh_token_is_not_an_access_token(self, client, session):
        response = client.get(
            "/v1/persons/me",
            headers={"Authorization": f"Bearer {session.refresh_token}"},
        )
        assert response.status_code == 401
