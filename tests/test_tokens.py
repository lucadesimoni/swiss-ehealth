# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Capability token issuance and verification."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from ehealth.security.crypto import KeyRing, b64u, b64u_decode, canonical_json
from ehealth.security.tokens import (
    Delegation,
    Scope,
    TokenClaims,
    TokenError,
    TokenService,
)

ISSUER = "https://test.dossier.ch"
AUDIENCE = "ch.ehealth.test"


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(b"\x33" * 32)


@pytest.fixture
def tokens(keyring) -> TokenService:
    return TokenService(keyring, issuer=ISSUER, audience=AUDIENCE)


def make_claims(**overrides) -> TokenClaims:
    now = datetime.now(UTC)
    defaults = dict(
        jti="grt_01J8Z3K7QF9M2C4V6X8B0N5RTD",
        kind="capability",
        issuer=ISSUER,
        subject_uid="hcp_01J8Z3K7QF9M2C4V6X8B0N5RTE",
        audience=AUDIENCE,
        purpose="treatment",
        scopes=[Scope.DOSSIER_READ, Scope.MEDICATION_READ],
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(minutes=10),
        dossier_uid="dos_01J8Z3K7QF9M2C4V6X8B0N5RTF",
        grant_uid="grt_01J8Z3K7QF9M2C4V6X8B0N5RTG",
        access_level="normal",
    )
    defaults.update(overrides)
    return TokenClaims(**defaults)


class TestRoundTrip:
    def test_issues_and_verifies(self, tokens):
        claims = make_claims()
        verified = tokens.verify(tokens.issue(claims))
        assert verified.jti == claims.jti
        assert verified.dossier_uid == claims.dossier_uid
        assert verified.scopes == claims.scopes

    def test_carries_the_delegation_chain(self, tokens):
        chain = [Delegation("pat_1", "vis_2", "2026-08-07T10:00:00Z")]
        verified = tokens.verify(tokens.issue(make_claims(delegation=chain)))
        assert verified.delegation[0].from_uid == "pat_1"

    def test_omits_absent_optional_claims(self, tokens):
        token = tokens.issue(make_claims(session_uid=None, organization_uid=None))
        payload = json.loads(b64u_decode(token.split(".")[1]))
        assert "ses" not in payload
        assert "org" not in payload


class TestScopes:
    def test_has_scope_is_exact(self, tokens):
        claims = tokens.verify(tokens.issue(make_claims()))
        assert claims.has_scope(Scope.DOSSIER_READ)
        assert not claims.has_scope(Scope.DOSSIER_WRITE)

    def test_admin_scope_implies_everything(self, tokens):
        claims = tokens.verify(tokens.issue(make_claims(scopes=[Scope.ADMIN])))
        assert claims.has_scope(Scope.MEDICATION_WRITE)

    def test_unknown_scope_is_rejected(self):
        with pytest.raises(TokenError, match="unknown scope"):
            Scope.parse_all(["dossier:read", "everything:always"])


class TestTampering:
    def test_rejects_a_modified_payload(self, tokens):
        """The classic attack: swap the dossier id and keep the signature."""
        token = tokens.issue(make_claims())
        header, payload, signature = token.split(".")
        claims = json.loads(b64u_decode(payload))
        claims["dos"] = "dos_01J8Z3K7QF9M2C4V6X8B0N5RZZ"
        forged = f"{header}.{b64u(canonical_json(claims))}.{signature}"
        with pytest.raises(TokenError, match="signature"):
            tokens.verify(forged)

    def test_rejects_the_none_algorithm(self, tokens):
        token = tokens.issue(make_claims())
        _, payload, _ = token.split(".")
        header = b64u(
            canonical_json({"alg": "none", "kid": "token-signing.v1", "typ": "CAP"})
        )
        with pytest.raises(TokenError, match="unsupported signature algorithm"):
            tokens.verify(f"{header}.{payload}.")

    def test_rejects_an_unimplemented_registered_algorithm(self, tokens):
        """ML-DSA is registered but not available; claiming it must fail
        closed rather than fall back to Ed25519."""
        _, payload, signature = tokens.issue(make_claims()).split(".")
        header = b64u(
            canonical_json(
                {"alg": "ML-DSA-65", "kid": "token-signing.v1", "typ": "CAP"}
            )
        )
        with pytest.raises(TokenError, match="unsupported signature algorithm"):
            tokens.verify(f"{header}.{payload}.{signature}")

    def test_rejects_a_token_signed_with_a_different_purpose_key(self, tokens, keyring):
        """Signing with the audit key must not authorise anything."""
        from ehealth.security.crypto import KeyPurpose

        audit_signer = keyring.signer(KeyPurpose.AUDIT_LEDGER)
        header = b64u(
            canonical_json({"alg": "Ed25519", "kid": audit_signer.kid, "typ": "CAP"})
        )
        payload = b64u(canonical_json(make_claims().to_payload()))
        signature = audit_signer.sign(f"{header}.{payload}".encode("ascii"))
        with pytest.raises(TokenError, match="non-token key"):
            tokens.verify(f"{header}.{payload}.{signature}")

    def test_rejects_a_foreign_key(self, keyring):
        mine = TokenService(keyring, issuer=ISSUER, audience=AUDIENCE)
        theirs = TokenService(KeyRing(b"\x44" * 32), issuer=ISSUER, audience=AUDIENCE)
        with pytest.raises(TokenError, match="signature"):
            mine.verify(theirs.issue(make_claims()))

    @pytest.mark.parametrize("token", ["", "a.b", "a.b.c.d", "not-a-token"])
    def test_rejects_structurally_broken_tokens(self, tokens, token):
        with pytest.raises(TokenError):
            tokens.verify(token)


class TestTimeAndBinding:
    def test_rejects_an_expired_token(self, tokens):
        past = datetime.now(UTC) - timedelta(hours=2)
        token = tokens.issue(
            make_claims(
                issued_at=past, not_before=past, expires_at=past + timedelta(minutes=1)
            )
        )
        with pytest.raises(TokenError, match="expired"):
            tokens.verify(token)

    def test_rejects_a_token_that_is_not_valid_yet(self, tokens):
        future = datetime.now(UTC) + timedelta(hours=1)
        token = tokens.issue(
            make_claims(not_before=future, expires_at=future + timedelta(minutes=10))
        )
        with pytest.raises(TokenError, match="not valid yet"):
            tokens.verify(token)

    def test_refuses_to_issue_beyond_the_policy_lifetime(self, keyring):
        service = TokenService(
            keyring, issuer=ISSUER, audience=AUDIENCE, max_ttl_seconds=600
        )
        now = datetime.now(UTC)
        with pytest.raises(TokenError, match="exceeds"):
            service.issue(
                make_claims(issued_at=now, expires_at=now + timedelta(hours=2))
            )

    def test_rejects_a_wrong_audience(self, tokens):
        """Audience binding stops a token minted for one service being
        replayed against another."""
        token = tokens.issue(make_claims(audience="ch.ehealth.other"))
        with pytest.raises(TokenError, match="audience"):
            tokens.verify(token)

    def test_rejects_a_wrong_issuer(self, tokens):
        token = tokens.issue(make_claims(issuer="https://evil.example"))
        with pytest.raises(TokenError, match="issuer"):
            tokens.verify(token)

    def test_tolerates_small_clock_skew(self, keyring):
        service = TokenService(
            keyring, issuer=ISSUER, audience=AUDIENCE, clock_skew_seconds=30
        )
        now = datetime.now(UTC)
        token = service.issue(
            make_claims(
                issued_at=now,
                not_before=now + timedelta(seconds=10),
                expires_at=now + timedelta(minutes=5),
            )
        )
        assert service.verify(token).jti


class TestHolderBinding:
    def test_unbound_tokens_need_no_key(self, tokens):
        claims = tokens.verify(tokens.issue(make_claims()))
        TokenService.check_holder_binding(claims, None)

    def test_bound_token_requires_the_matching_key(self, tokens):
        holder = b64u(b"\x55" * 32)
        claims = tokens.verify(
            tokens.issue(make_claims(cnf_jkt=TokenService.thumbprint(holder)))
        )
        TokenService.check_holder_binding(claims, holder)
        with pytest.raises(TokenError, match="does not match"):
            TokenService.check_holder_binding(claims, b64u(b"\x66" * 32))
        with pytest.raises(TokenError, match="no key was presented"):
            TokenService.check_holder_binding(claims, None)
