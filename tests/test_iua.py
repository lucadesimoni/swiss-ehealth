# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""IUA access tokens, end to end (CH EPR FHIR v5.0.0: ITI-71, ITI-72, ITI-103).

Registered clients obtain tokens over signed requests; MHD, PIXm/PDQm and
CH:ATC accept them; and a token is only ever as good as the patient's
consent is *at the moment it is used*.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import ClassVar
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from sqlalchemy import select

from ehealth.config import Environment, IuaClientSettings, Settings
from ehealth.models.audit import AuditAction, AuditEvent
from ehealth.models.governance import IssuedToken
from ehealth.security.crypto import b64u, b64u_decode, sha256
from ehealth.security.httpsig import sign_request
from ehealth.services.auth import AssurancePolicy
from ehealth.services.iua import (
    PURPOSE_OF_USE_SYSTEM,
    ROLE_SYSTEM,
    ROLE_SYSTEM_ALTERNATIVE,
    format_person_id,
    parse_person_id,
)
from tests.conftest import ADMIN_KEY
from tests.document_helpers import PDF, SPID, bundle, published_uid
from tests.test_oidc_provider import ISSUER as IDP_ISSUER
from tests.test_oidc_provider import FakeProvider, _jws, make_client

TOKEN_URL = "http://testserver/v1/iua/token"
REDIRECT = "https://portal.example.ch/callback"
GLN = "7601000000002"  # Beat Arzt's, see conftest


def _pem_public(key) -> str:
    return (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


PORTAL_KEY = ec.generate_private_key(ec.SECP256R1())
ARCHIVE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PORTAL_SECRET = "portal-secret-" + "p" * 32
ARCHIVE_SECRET = "archive-secret-" + "a" * 32


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


CLIENTS = (
    IuaClientSettings(
        client_id="portal",
        name="Patientenportal Test",
        client_secret_sha256=_hash(PORTAL_SECRET),
        public_key_pem=_pem_public(PORTAL_KEY),
        public_key_id="portal-2026-09",
        redirect_uris=(REDIRECT,),
        grant_types=(
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        ),
        idp_client_ids=("portal-at-idp",),
    ),
    IuaClientSettings(
        client_id="archive",
        name="Klinikarchiv Test",
        client_secret_sha256=_hash(ARCHIVE_SECRET),
        public_key_pem=_pem_public(ARCHIVE_KEY),
        grant_types=("client_credentials",),
        technical_user_gln=GLN,
    ),
)

CLIENT_KEYS = {
    "portal": (PORTAL_SECRET, PORTAL_KEY, "portal-2026-09"),
    "archive": (ARCHIVE_SECRET, ARCHIVE_KEY, None),
}


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
        iua_clients=CLIENTS,
    )


# -- helpers --------------------------------------------------------------------


def scope(role: str | None = None, purpose: str | None = None) -> str:
    parts = ["openid"]
    if purpose:
        parts.append(f"purpose_of_use={PURPOSE_OF_USE_SYSTEM}|{purpose}")
    if role:
        parts.append(f"subject_role={ROLE_SYSTEM}|{role}")
    return " ".join(parts)


def token_request(
    client,
    form: dict,
    *,
    client_id: str = "archive",
    secret: str | None = None,
    sign: bool = True,
    key=None,
    body_override: bytes | None = None,
    **sign_kwargs,
):
    registered_secret, registered_key, keyid = CLIENT_KEYS[client_id]
    body = urlencode(form).encode()
    basic = f"{client_id}:{secret or registered_secret}".encode()
    headers = {
        "Authorization": "Basic " + base64.b64encode(basic).decode(),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    if sign:
        headers.update(
            sign_request(
                private_key=key or registered_key,
                method="POST",
                target_uri=TOKEN_URL,
                headers=headers,
                body=body,
                keyid=keyid,
                **sign_kwargs,
            )
        )
    return client.post("/v1/iua/token", content=body_override or body, headers=headers)


def technical_user_token(client, world, **extra):
    form = {
        "grant_type": "client_credentials",
        "scope": scope("TCU", "AUTO"),
        "principal_id": GLN,
        "principal": "Dr. med. Beat Arzt",
        "person_id": format_person_id(world.patient.spid),
        **extra,
    }
    response = token_request(client, form)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def authorize(client, params: dict, *, session=None):
    query = {
        "response_type": "code",
        "client_id": "portal",
        "redirect_uri": REDIRECT,
        "state": "st-1",
        "code_challenge": b64u(sha256(b"verifier-" + b"v" * 43)),
        "code_challenge_method": "S256",
        **params,
    }
    headers = session.auth_header if session else {}
    return client.get(
        "/v1/iua/authorize",
        params=query,
        headers=headers,
        follow_redirects=False,
    )


def code_from(response) -> str:
    assert response.status_code == 302, response.text
    location = urlparse(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == REDIRECT
    query = parse_qs(location.query)
    assert query["state"] == ["st-1"]
    return query["code"][0]


def redeem(client, code: str, *, verifier: str = "verifier-" + "v" * 43, **extra):
    return token_request(
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": REDIRECT,
            "client_id": "portal",
            **extra,
        },
        client_id="portal",
    )


def session_token(client, session, world, *, role, purpose, spid=None):
    params = {"scope": scope(role, purpose)}
    if spid is not False:
        params["person_id"] = format_person_id(spid or world.patient.spid)
    response = redeem(client, code_from(authorize(client, params, session=session)))
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def claims_of(token: str) -> dict:
    return json.loads(b64u_decode(token.split(".")[1]))


def find(client, token, spid):
    return client.get(
        "/v1/fhir/DocumentReference",
        params={"patient.identifier": f"{SPID}|{spid}"},
        headers=bearer(token),
    )


def publish(client, token, spid, **kwargs):
    return client.post("/v1/fhir", json=bundle(spid, **kwargs), headers=bearer(token))


def denials(db, action=AuditAction.TOKEN_REJECTED) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.execute(select(AuditEvent).where(AuditEvent.action == action.value))
        .scalars()
        .all()
    )


# -- ITI-103 ---------------------------------------------------------------------


class TestMetadata:
    def test_smart_configuration_describes_the_server(self, client):
        response = client.get("/v1/fhir/.well-known/smart-configuration")
        assert response.status_code == 200
        body = response.json()
        for required in (
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "response_types_supported",
            "grant_types_supported",
            "capabilities",
        ):
            assert required in body
        assert set(body["grant_types_supported"]) >= {
            "client_credentials",
            "authorization_code",
            "urn:ietf:params:oauth:grant-type:jwt-bearer",
        }
        assert "client_secret_basic" in body["token_endpoint_auth_methods_supported"]
        assert body["access_token_format"] == ["urn:ietf:params:oauth:token-type:jwt"]

    def test_the_capability_statement_points_to_iua(self, client):
        rest = client.get("/v1/fhir/metadata").json()["rest"][0]
        assert rest["security"]["service"][0]["coding"][0]["code"] == "SMART-on-FHIR"
        uris = {
            e["url"]: e["valueUri"]
            for e in rest["security"]["extension"][0]["extension"]
        }
        assert uris["token"].endswith("/v1/iua/token")

    def test_the_jwks_publishes_an_rs256_key(self, client):
        (key,) = client.get("/v1/iua/jwks.json").json()["keys"]
        assert key["kty"] == "RSA" and key["alg"] == "RS256"
        assert "d" not in key  # never the private half


# -- ITI-71: technical user ---------------------------------------------------


class TestTechnicalUser:
    def test_an_archive_obtains_an_extended_token(self, client, world):
        token = technical_user_token(client, world)
        header = json.loads(b64u_decode(token.split(".")[0]))
        assert header["alg"] == "RS256" and header["typ"] == "at+jwt"
        claims = claims_of(token)
        assert claims["iss"] == "https://test.dossier.ch/iua"
        assert claims["aud"] == "https://test.dossier.ch/v1/fhir"
        assert claims["exp"] - claims["iat"] == 300
        iua = claims["extensions"]["ihe_iua"]
        assert iua["person_id"] == (
            f"{world.patient.spid}^^^&2.16.756.5.30.1.127.3.10.3&ISO"
        )
        assert iua["subject_role"] == {"system": ROLE_SYSTEM, "code": "TCU"}
        assert iua["purpose_of_use"] == {
            "system": PURPOSE_OF_USE_SYSTEM,
            "code": "AUTO",
        }
        assert claims["extensions"]["ch_epr"] == {
            "user_id": GLN,
            "user_id_qualifier": "urn:gs1:gln",
        }
        assert claims["extensions"]["ch_delegation"] == {
            "principal": "Dr. med. Beat Arzt",
            "principal_id": GLN,
        }

    def test_the_archive_writes_a_document_with_it(self, client, world, db):
        token = technical_user_token(client, world)
        response = publish(client, token, world.patient.spid)
        assert response.status_code == 200, response.text
        uid = published_uid(response)
        from ehealth.models.clinical import DossierDocument

        document = db.get(DossierDocument, uid)
        # Authored by the professional the archive acts for.
        assert document.author_uid == world.doctor.uid

    def test_the_archive_cannot_read(self, client, world):
        token = technical_user_token(client, world)
        assert publish(client, token, world.patient.spid).status_code == 200
        assert find(client, token, world.patient.spid).status_code == 401

    def test_the_legacy_role_code_system_is_accepted(self, client, world):
        form = {
            "grant_type": "client_credentials",
            "scope": (
                f"purpose_of_use={PURPOSE_OF_USE_SYSTEM}|AUTO "
                f"subject_role={ROLE_SYSTEM_ALTERNATIVE}|TCU"
            ),
            "principal_id": GLN,
        }
        response = token_request(client, form)
        assert response.status_code == 200, response.text
        # A basic token: no person_id, no record.
        assert (
            "person_id"
            not in claims_of(response.json()["access_token"])["extensions"]["ihe_iua"]
        )

    def test_another_principal_is_refused(self, client, world, db):
        response = token_request(
            client,
            {
                "grant_type": "client_credentials",
                "scope": scope("TCU", "AUTO"),
                "principal_id": "7601000000019",
            },
        )
        assert response.status_code == 401
        assert response.json() == {"error": "invalid_grant"}
        (event,) = denials(db, AuditAction.ACCESS_DENIED)
        assert "principal_id" in event.detail["reason"]

    def test_the_tcu_role_and_auto_purpose_are_required(self, client, world):
        response = token_request(
            client,
            {
                "grant_type": "client_credentials",
                "scope": scope("HCP", "NORM"),
                "principal_id": GLN,
            },
        )
        assert response.status_code == 401

    def test_a_wrong_secret_is_refused(self, client, world):
        response = token_request(
            client,
            {"grant_type": "client_credentials", "scope": scope("TCU", "AUTO")},
            secret="guess",
        )
        assert response.status_code == 401
        assert response.json() == {"error": "invalid_client"}

    def test_an_unregistered_grant_type_is_refused(self, client, world):
        response = token_request(
            client, {"grant_type": "authorization_code", "code": "x"}
        )
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized_client"}


class TestSignedRequests:
    """RFC 9421: the guide requires every token request to be signed."""

    form: ClassVar[dict[str, str]] = {
        "grant_type": "client_credentials",
        "scope": scope("TCU", "AUTO"),
        "principal_id": GLN,
    }

    def test_an_unsigned_request_is_refused(self, client, world):
        assert token_request(client, self.form, sign=False).status_code == 401

    def test_a_request_signed_with_another_key_is_refused(self, client, world):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        assert token_request(client, self.form, key=other).status_code == 401

    def test_a_tampered_body_is_refused(self, client, world):
        tampered = urlencode({**self.form, "principal_id": "7601000000019"}).encode()
        response = token_request(client, self.form, body_override=tampered)
        assert response.status_code == 401

    def test_a_long_lived_signature_is_refused(self, client, world):
        assert token_request(client, self.form, lifetime=300).status_code == 401

    def test_a_replayed_old_signature_is_refused(self, client, world):
        old = int(time.time()) - 300
        assert token_request(client, self.form, created=old).status_code == 401

    def test_repeated_parameters_are_refused(self, client, world):
        body = urlencode(self.form).encode() + b"&principal_id=7601000000019"
        response = token_request(client, self.form, body_override=body)
        assert response.status_code == 400


# -- ITI-71: code flow ------------------------------------------------------------


class TestCodeFlow:
    def test_a_patient_reads_their_own_record(self, client, world, patient):
        archive = technical_user_token(client, world)
        uid = published_uid(publish(client, archive, world.patient.spid))
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        claims = claims_of(token)
        assert claims["extensions"]["ch_epr"] == {
            "user_id": world.patient.spid,
            "user_id_qualifier": "urn:e-health-suisse:2015:epr-spid",
        }
        body = find(client, token, world.patient.spid).json()
        assert [e["resource"]["id"] for e in body["entry"]] == [uid]
        content = client.get(f"/v1/fhir/Binary/{uid}", headers=bearer(token))
        assert content.status_code == 200 and content.content == PDF

    def test_a_patient_may_not_ask_for_another_record(self, client, world, patient):
        response = redeem(
            client,
            code_from(
                authorize(
                    client,
                    {
                        "scope": scope("PAT", "NORM"),
                        "person_id": format_person_id(world.doctor.spid),
                    },
                    session=patient,
                )
            ),
        )
        assert response.status_code == 401

    def test_a_professional_reads_under_the_patients_consent(
        self, client, world, doctor, patient
    ):
        archive = technical_user_token(client, world)
        publish(client, archive, world.patient.spid)
        token = session_token(client, doctor, world, role="HCP", purpose="NORM")
        assert claims_of(token)["extensions"]["ch_epr"]["user_id"] == GLN
        assert find(client, token, world.patient.spid).json()["total"] == 1

        # The patient excludes the doctor. The token was valid a moment ago
        # and still verifies; the next request is refused all the same.
        rule = client.post(
            "/v1/consent/rules",
            headers=patient.auth_header,
            json={
                "subject_type": "person",
                "subject_uid": world.doctor.uid,
                "effect": "deny",
                "access_level": "normal",
            },
        )
        assert rule.status_code == 201, rule.text
        assert find(client, token, world.patient.spid).status_code == 401

    def test_emergency_access_is_recorded(self, client, world, doctor, db):
        token = session_token(client, doctor, world, role="HCP", purpose="EMER")
        assert find(client, token, world.patient.spid).status_code == 200
        (event,) = denials(db, AuditAction.EMERGENCY_ACCESS)
        assert event.detail["notify_patient"] is True

    def test_a_token_for_one_record_cannot_reach_another(self, client, world, doctor):
        token = session_token(client, doctor, world, role="HCP", purpose="NORM")
        # Beat is also a patient. Asking for his record with Anna's token:
        response = find(client, token, world.doctor.spid)
        assert response.json()["total"] == 0
        written = publish(client, token, world.doctor.spid)
        assert written.status_code == 403

    def test_a_code_is_single_use_and_replay_revokes(self, client, world, patient, db):
        code = code_from(
            authorize(
                client,
                {
                    "scope": scope("PAT", "NORM"),
                    "person_id": format_person_id(world.patient.spid),
                },
                session=patient,
            )
        )
        first = redeem(client, code)
        assert first.status_code == 200
        token = first.json()["access_token"]
        assert find(client, token, world.patient.spid).status_code == 200
        assert redeem(client, code).status_code == 401
        # The token issued from the replayed code is revoked with it.
        assert find(client, token, world.patient.spid).status_code == 401

    def test_pkce_is_enforced(self, client, world, patient):
        code = code_from(
            authorize(client, {"scope": scope("PAT", "NORM")}, session=patient)
        )
        assert redeem(client, code, verifier="w" * 52).status_code == 401

    def test_pkce_is_required(self, client, world, patient):
        response = authorize(
            client,
            {"scope": scope("PAT", "NORM"), "code_challenge_method": "plain"},
            session=patient,
        )
        assert response.status_code == 400

    def test_an_unregistered_redirect_is_never_followed(self, client, world, patient):
        response = authorize(
            client,
            {"scope": scope("PAT", "NORM"), "redirect_uri": "https://evil.example/cb"},
            session=patient,
        )
        assert response.status_code == 401
        assert "location" not in response.headers

    def test_a_code_bound_to_another_client_does_not_redeem(
        self, client, world, patient
    ):
        code = code_from(
            authorize(client, {"scope": scope("PAT", "NORM")}, session=patient)
        )
        forged = code[:-4] + ("AAAA" if not code.endswith("AAAA") else "BBBB")
        assert redeem(client, forged).status_code == 401

    def test_without_a_login_the_token_request_needs_an_id_token(self, client, world):
        code = code_from(authorize(client, {"scope": scope("PAT", "NORM")}))
        assert redeem(client, code).status_code == 401

    def test_unsupported_roles_are_refused(self, client, world, doctor):
        for role in ("ASS", "REP"):
            code = code_from(
                authorize(
                    client,
                    {
                        "scope": scope(role, "NORM"),
                        "person_id": format_person_id(world.patient.spid),
                    },
                    session=doctor,
                )
            )
            assert redeem(client, code).status_code == 401

    def test_smart_launch_is_refused_rather_than_ignored(self, client, patient):
        response = authorize(
            client, {"scope": "launch " + scope("PAT", "NORM")}, session=patient
        )
        assert response.status_code == 401


# -- ITI-71: an ID token presented by the portal -------------------------------------


@pytest.fixture
def idp(container, client, world):
    """A real-signature provider whose ID tokens the portal presents."""
    provider = FakeProvider(alg="RS256")
    verifier = make_client(provider)
    container.iua._verifiers[IDP_ISSUER] = verifier
    container.iua._policies[IDP_ISSUER] = AssurancePolicy(
        accepted_acr=frozenset({"loa-2", "loa-3"}),
        mfa_acr=frozenset({"loa-3"}),
    )
    linked = client.post(
        "/v1/auth/accounts/link",
        json={
            "person_uid": world.doctor.uid,
            "issuer": IDP_ISSUER,
            "subject": "beat-at-idp",
            "email": "beat.arzt@example.ch",
        },
    )
    assert linked.status_code == 201, linked.text
    return provider


def id_token(provider, **overrides):
    now = int(time.time())
    claims = {
        "iss": IDP_ISSUER,
        "sub": "beat-at-idp",
        "aud": "portal-at-idp",
        "iat": now,
        "exp": now + 300,
        "acr": "loa-3",
        **overrides,
    }
    kid, key = provider.signing
    return _jws(key, "RS256", kid, claims)


class TestPresentedIdToken:
    def bearer_grant(self, client, world, assertion):
        return token_request(
            client,
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": assertion,
                "scope": scope("HCP", "NORM"),
                "person_id": format_person_id(world.patient.spid),
            },
            client_id="portal",
        )

    def test_a_fresh_two_factor_id_token_is_accepted(self, client, world, idp):
        response = self.bearer_grant(client, world, id_token(idp))
        assert response.status_code == 200, response.text
        token = response.json()["access_token"]
        assert find(client, token, world.patient.spid).status_code == 200

    def test_the_code_flow_takes_it_as_client_assertion(self, client, world, idp):
        code = code_from(
            authorize(
                client,
                {
                    "scope": scope("HCP", "NORM"),
                    "person_id": format_person_id(world.patient.spid),
                },
            )
        )
        response = redeem(
            client,
            code,
            client_assertion_type=(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            client_assertion=id_token(idp),
        )
        assert response.status_code == 200, response.text

    @pytest.mark.parametrize(
        "overrides",
        [
            {"acr": "loa-2"},  # accepted for login, but no second factor
            {"acr": "loa-1"},
            {"aud": "some-other-app"},
            {"iat": int(time.time()) - 3600, "exp": int(time.time()) + 300},
            {"exp": int(time.time()) - 60},
            {"sub": "nobody-we-know"},
        ],
        ids=["one-factor", "too-weak", "audience", "stale", "expired", "unlinked"],
    )
    def test_weak_or_foreign_id_tokens_are_refused(self, client, world, idp, overrides):
        response = self.bearer_grant(client, world, id_token(idp, **overrides))
        assert response.status_code == 401

    def test_a_forged_id_token_is_refused(self, client, world, idp):
        forger = FakeProvider(alg="RS256")
        _, key = forger.signing
        now = int(time.time())
        forged = _jws(
            key,
            "RS256",
            idp.signing[0],
            {
                "iss": IDP_ISSUER,
                "sub": "beat-at-idp",
                "aud": "portal-at-idp",
                "iat": now,
                "exp": now + 300,
                "acr": "loa-3",
            },
        )
        assert self.bearer_grant(client, world, forged).status_code == 401


# -- ITI-72: the resource server --------------------------------------------------


class TestResourceServer:
    def test_a_modified_token_is_refused(self, client, world, patient):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        head, body, signature = token.split(".")
        claims = json.loads(b64u_decode(body))
        claims["extensions"]["ihe_iua"]["person_id"] = format_person_id(
            world.doctor.spid
        )
        forged = f"{head}.{b64u(json.dumps(claims).encode())}.{signature}"
        assert find(client, forged, world.doctor.spid).status_code == 401

    def test_a_token_re_signed_with_another_key_is_refused(
        self, client, world, patient
    ):
        """Same header, same kid, same (registered) claims — only the key
        differs. Nothing but the signature check can catch this."""
        from ehealth.services.iua import IuaSigningKey

        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        attacker = IuaSigningKey("", "iua-1")
        forged = attacker.sign(claims_of(token))
        assert find(client, forged, world.patient.spid).status_code == 401
        assert find(client, token, world.patient.spid).status_code == 200

    def test_a_token_for_another_resource_server_is_refused(
        self, client, world, patient, container
    ):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        claims = {**claims_of(token), "aud": "https://other-community.ch/fhir"}
        elsewhere = container.iua._key.sign(claims)
        assert find(client, elsewhere, world.patient.spid).status_code == 401

    def test_alg_none_is_refused(self, client, world, patient):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        _, body, _ = token.split(".")
        head = b64u(json.dumps({"alg": "none", "typ": "at+jwt"}).encode())
        assert find(client, f"{head}.{body}.", world.patient.spid).status_code == 401

    def test_a_revoked_token_is_refused(self, client, world, patient, db):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        record = db.get(IssuedToken, claims_of(token)["jti"])
        from ehealth.db import utcnow

        record.revoked_at = utcnow()
        db.commit()
        assert find(client, token, world.patient.spid).status_code == 401

    def test_an_expired_token_is_refused(self, client, world, patient, monkeypatch):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        real = time.time
        monkeypatch.setattr("ehealth.services.iua.time.time", lambda: real() + 3600)
        assert find(client, token, world.patient.spid).status_code == 401

    def test_a_basic_token_does_not_reach_documents(self, client, world, doctor):
        token = session_token(
            client, doctor, world, role="HCP", purpose="NORM", spid=False
        )
        assert "person_id" not in claims_of(token)["extensions"]["ihe_iua"]
        assert find(client, token, world.patient.spid).status_code == 401

    def test_a_basic_token_reaches_pixm(self, client, world, doctor):
        token = session_token(
            client, doctor, world, role="HCP", purpose="NORM", spid=False
        )
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{SPID}|{world.patient.spid}"},
            headers=bearer(token),
        )
        assert response.status_code == 200, response.text

    def test_a_patient_token_does_not_reach_pixm(self, client, world, patient):
        token = session_token(
            client, patient, world, role="PAT", purpose="NORM", spid=False
        )
        response = client.get(
            "/v1/fhir/Patient/$ihe-pix",
            params={"sourceIdentifier": f"{SPID}|{world.patient.spid}"},
            headers=bearer(token),
        )
        assert response.status_code == 403

    def test_the_patient_reads_their_audit_trail(self, client, world, patient):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        response = client.get(
            "/v1/fhir/AuditEvent",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=bearer(token),
        )
        assert response.status_code == 200, response.text
        assert response.json()["resourceType"] == "Bundle"

    def test_a_professional_does_not_read_the_audit_trail(self, client, world, doctor):
        token = session_token(client, doctor, world, role="HCP", purpose="NORM")
        response = client.get(
            "/v1/fhir/AuditEvent",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers=bearer(token),
        )
        assert response.status_code == 401

    def test_a_capability_and_an_iua_token_together_are_refused(
        self, client, world, patient, headers
    ):
        token = session_token(client, patient, world, role="PAT", purpose="NORM")
        response = client.get(
            "/v1/fhir/DocumentReference",
            params={"patient.identifier": f"{SPID}|{world.patient.spid}"},
            headers={**bearer(token), "X-Capability": headers["X-Capability"]},
        )
        assert response.status_code == 400

    def test_refusals_are_in_the_ledger(self, client, world, db):
        token = technical_user_token(client, world)
        find(client, token, world.patient.spid)
        (event,) = denials(db)
        assert event.detail["kind"] == "iua"
        assert "document:read" in event.detail["reason"]


def test_person_id_must_be_an_epr_spid():
    assert parse_person_id(format_person_id("761337610411353650")) == (
        "761337610411353650"
    )
    from ehealth.services.iua import IuaError

    for bad in (
        "761337610411353650^^^&2.16.756.5.32&ISO",  # an AHV number domain
        "761337610411353650",
        "abc^^^&2.16.756.5.30.1.127.3.10.3&ISO",
    ):
        with pytest.raises(IuaError):
            parse_person_id(bad)
