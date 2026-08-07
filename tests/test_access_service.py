# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Grants, capability tokens, visitor access, revocation and break-glass.

These exercise the database-backed half of authorisation: the part that can
say "the token is cryptographically fine, and it is still allowed *right
now*".
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from ehealth.db import utcnow
from ehealth.models.audit import AuditEvent
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.core import PersonRoleKind
from ehealth.models.governance import GrantStatus, IssuedToken, RuleEffect
from ehealth.security.tokens import Scope
from ehealth.services.access import AccessError
from ehealth.services.dossier import DocumentInput
from ehealth.services.medication import StatementInput
from ehealth.models.clinical import MedicationEventKind


TREATMENT_SCOPES = [
    Scope.DOSSIER_READ,
    Scope.DOCUMENT_READ,
    Scope.DOCUMENT_WRITE,
    Scope.MEDICATION_READ,
    Scope.MEDICATION_WRITE,
]


@pytest.fixture
def doctor_grant(container, db, system_actor, world):
    grant = container.access.issue_grant(
        db,
        system_actor,
        dossier=world.dossier,
        grantee=world.doctor,
        granted_by=world.patient,
        purpose=Purpose.TREATMENT,
        scopes=TREATMENT_SCOPES,
    )
    db.commit()
    return grant


@pytest.fixture
def doctor_token(container, db, system_actor, doctor_grant):
    capability = container.access.mint(db, system_actor, grant=doctor_grant)
    db.commit()
    return capability


class TestGranting:
    def test_issues_a_bounded_grant(self, doctor_grant):
        assert doctor_grant.status == GrantStatus.ACTIVE.value
        assert doctor_grant.valid_until > doctor_grant.valid_from
        assert doctor_grant.access_level == Confidentiality.NORMAL.value

    def test_clamps_the_grant_to_what_consent_allows(
        self, container, db, system_actor, world
    ):
        """A grant must never exceed the patient's own settings, so a
        compromised granting path cannot escalate."""
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ],
            access_level=Confidentiality.SECRET,
        )
        assert grant.access_level == Confidentiality.NORMAL.value

    def test_refuses_a_grant_the_patient_excluded(
        self, container, db, system_actor, world
    ):
        container.consents.add_rule(
            db,
            system_actor,
            world.consent,
            subject_type="person",
            subject_uid=world.doctor.uid,
            effect=RuleEffect.DENY,
        )
        db.commit()
        with pytest.raises(AccessError):
            container.access.issue_grant(
                db,
                system_actor,
                dossier=world.dossier,
                grantee=world.doctor,
                granted_by=world.patient,
                purpose=Purpose.TREATMENT,
                scopes=[Scope.DOSSIER_READ],
            )

    def test_records_the_denial_in_the_trail(self, container, db, system_actor, world):
        container.consents.add_rule(
            db,
            system_actor,
            world.consent,
            subject_type="person",
            subject_uid=world.doctor.uid,
            effect=RuleEffect.DENY,
        )
        with pytest.raises(AccessError):
            container.access.issue_grant(
                db,
                system_actor,
                dossier=world.dossier,
                grantee=world.doctor,
                granted_by=world.patient,
                purpose=Purpose.TREATMENT,
                scopes=[Scope.DOSSIER_READ],
            )
        denials = db.execute(
            select(AuditEvent).where(AuditEvent.action == "access.denied")
        ).scalars().all()
        assert len(denials) == 1


class TestVisitorGrants:
    def test_clamps_scopes_to_read_only(self, container, db, system_actor, world):
        """Even if the caller asks for write access, a visitor cannot get it."""
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.visitor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ, Scope.DOCUMENT_WRITE, Scope.MEDICATION_WRITE],
            grantee_role=PersonRoleKind.VISITOR,
            max_uses=3,
        )
        assert set(grant.scopes) == {"dossier:read"}
        assert grant.access_level == Confidentiality.NORMAL.value
        assert grant.max_uses == 3

    def test_only_the_patient_may_grant_visitor_access(
        self, container, db, system_actor, world
    ):
        with pytest.raises(AccessError, match="only the patient"):
            container.access.issue_grant(
                db,
                system_actor,
                dossier=world.dossier,
                grantee=world.visitor,
                granted_by=world.doctor,
                purpose=Purpose.TREATMENT,
                scopes=[Scope.DOSSIER_READ],
                grantee_role=PersonRoleKind.VISITOR,
            )

    def test_refuses_when_no_permissible_scope_remains(
        self, container, db, system_actor, world
    ):
        with pytest.raises(AccessError, match="no permissible scope"):
            container.access.issue_grant(
                db,
                system_actor,
                dossier=world.dossier,
                grantee=world.visitor,
                granted_by=world.patient,
                purpose=Purpose.TREATMENT,
                scopes=[Scope.DOSSIER_WRITE],
                grantee_role=PersonRoleKind.VISITOR,
            )

    def test_visitor_access_expires_and_is_use_capped(
        self, container, db, system_actor, world
    ):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.visitor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ],
            grantee_role=PersonRoleKind.VISITOR,
            ttl_seconds=3600,
            max_uses=2,
        )
        capability = container.access.mint(db, system_actor, grant=grant)
        db.commit()
        container.access.authorize(
            db, capability.token, required_scope=Scope.DOSSIER_READ
        )
        container.access.authorize(
            db, capability.token, required_scope=Scope.DOSSIER_READ
        )
        db.commit()
        with pytest.raises(AccessError):
            container.access.authorize(
                db, capability.token, required_scope=Scope.DOSSIER_READ
            )


class TestMinting:
    def test_registers_the_token_so_it_stays_revocable(
        self, container, db, doctor_token
    ):
        """A bearer token that cannot be revoked has no place in a health
        record."""
        assert db.get(IssuedToken, doctor_token.jti) is not None

    def test_a_token_never_outlives_its_grant(
        self, container, db, system_actor, world
    ):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ],
            ttl_seconds=120,
        )
        capability = container.access.mint(
            db, system_actor, grant=grant, ttl_seconds=3600
        )
        assert capability.expires_at <= grant.valid_until

    def test_refuses_to_mint_against_a_revoked_grant(
        self, container, db, system_actor, doctor_grant
    ):
        container.access.revoke_grant(
            db, system_actor, doctor_grant, reason="no longer treating"
        )
        with pytest.raises(AccessError, match="not active"):
            container.access.mint(db, system_actor, grant=doctor_grant)


class TestAuthorising:
    def test_accepts_a_live_token(self, container, db, doctor_token, world):
        access = container.access.authorize(
            db, doctor_token.token, required_scope=Scope.DOSSIER_READ
        )
        assert access.dossier_uid == world.dossier.uid
        assert access.max_level is Confidentiality.NORMAL

    def test_counts_each_use(self, container, db, doctor_token):
        container.access.authorize(
            db, doctor_token.token, required_scope=Scope.DOSSIER_READ
        )
        db.commit()
        assert db.get(IssuedToken, doctor_token.jti).use_count == 1

    def test_rejects_a_missing_scope(self, container, db, system_actor, world):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.TREATMENT,
            scopes=[Scope.DOSSIER_READ],
        )
        capability = container.access.mint(db, system_actor, grant=grant)
        db.commit()
        with pytest.raises(AccessError):
            container.access.authorize(
                db, capability.token, required_scope=Scope.MEDICATION_WRITE
            )

    def test_rejects_a_token_for_another_dossier(
        self, container, db, doctor_token
    ):
        with pytest.raises(AccessError):
            container.access.authorize(
                db,
                doctor_token.token,
                required_scope=Scope.DOSSIER_READ,
                dossier_uid="dos_01J8Z3K7QF9M2C4V6X8B0N5RZZ",
            )

    def test_rejects_an_unregistered_token(self, container, db, system_actor, world):
        """A token signed by us but absent from the registry means the
        registry was bypassed — refuse rather than trust the signature."""
        from ehealth.security.tokens import TokenClaims

        now = utcnow()
        forged = container.tokens.issue(
            TokenClaims(
                jti="grt_01J8Z3K7QF9M2C4V6X8B0N5RZZ",
                kind="capability",
                issuer=container.tokens.issuer,
                subject_uid=world.doctor.uid,
                audience=container.tokens.audience,
                purpose="treatment",
                scopes=[Scope.DOSSIER_READ],
                issued_at=now,
                not_before=now,
                expires_at=now + timedelta(minutes=5),
                dossier_uid=world.dossier.uid,
            )
        )
        with pytest.raises(AccessError):
            container.access.authorize(
                db, forged, required_scope=Scope.DOSSIER_READ
            )

    def test_revoking_the_grant_kills_live_tokens(
        self, container, db, system_actor, doctor_grant, doctor_token
    ):
        container.access.revoke_grant(
            db, system_actor, doctor_grant, reason="treatment ended"
        )
        db.commit()
        assert db.get(IssuedToken, doctor_token.jti).revoked_at is not None
        with pytest.raises(AccessError):
            container.access.authorize(
                db, doctor_token.token, required_scope=Scope.DOSSIER_READ
            )

    def test_withdrawing_consent_kills_everything_immediately(
        self, container, db, system_actor, world, doctor_token
    ):
        """Consent re-checked at use time, not trusted from issue time: a
        patient who withdraws now is protected from a token minted a minute
        ago."""
        container.consents.withdraw(
            db, system_actor, world.consent, reason="patient left the system"
        )
        db.commit()
        with pytest.raises(AccessError):
            container.access.authorize(
                db, doctor_token.token, required_scope=Scope.DOSSIER_READ
            )

    def test_adding_a_deny_rule_takes_effect_on_the_next_use(
        self, container, db, system_actor, world, doctor_token
    ):
        container.access.authorize(
            db, doctor_token.token, required_scope=Scope.DOSSIER_READ
        )
        container.consents.add_rule(
            db,
            system_actor,
            world.consent,
            subject_type="person",
            subject_uid=world.doctor.uid,
            effect=RuleEffect.DENY,
        )
        db.commit()
        with pytest.raises(AccessError):
            container.access.authorize(
                db, doctor_token.token, required_scope=Scope.DOSSIER_READ
            )

    def test_records_every_rejection(self, container, db, doctor_token):
        with pytest.raises(AccessError):
            container.access.authorize(
                db, "not-a-token", required_scope=Scope.DOSSIER_READ
            )
        db.commit()
        rejections = db.execute(
            select(AuditEvent).where(AuditEvent.action == "token.rejected")
        ).scalars().all()
        assert len(rejections) == 1
        assert rejections[0].outcome == "denied"


class TestEmergencyAccess:
    @pytest.fixture
    def emergency_token(self, container, db, system_actor, world):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.EMERGENCY,
            scopes=[Scope.DOSSIER_READ, Scope.DOCUMENT_READ, Scope.MEDICATION_READ],
            note="unconscious patient, ED",
        )
        capability = container.access.mint(db, system_actor, grant=grant)
        db.commit()
        return capability

    def test_reaches_restricted_but_never_secret(
        self, container, db, emergency_token
    ):
        access = container.access.authorize(
            db, emergency_token.token, required_scope=Scope.DOSSIER_READ
        )
        assert access.max_level is Confidentiality.RESTRICTED

    def test_writes_a_dedicated_emergency_event(
        self, container, db, emergency_token
    ):
        container.access.authorize(
            db, emergency_token.token, required_scope=Scope.DOSSIER_READ
        )
        db.commit()
        events = db.execute(
            select(AuditEvent).where(AuditEvent.action == "access.emergency")
        ).scalars().all()
        assert len(events) == 1
        assert events[0].detail["notify_patient"] is True

    def test_overrides_an_exclusion_rule(
        self, container, db, system_actor, world
    ):
        container.consents.add_rule(
            db,
            system_actor,
            world.consent,
            subject_type="person",
            subject_uid=world.doctor.uid,
            effect=RuleEffect.DENY,
        )
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.doctor,
            granted_by=world.patient,
            purpose=Purpose.EMERGENCY,
            scopes=[Scope.DOSSIER_READ],
        )
        assert grant.status == GrantStatus.ACTIVE.value


class TestConfidentialityFiltering:
    @pytest.fixture
    def patient_access(self, container, db, system_actor, world):
        grant = container.access.issue_grant(
            db,
            system_actor,
            dossier=world.dossier,
            grantee=world.patient,
            granted_by=world.patient,
            purpose=Purpose.PATIENT_ACCESS,
            grantee_role=PersonRoleKind.PATIENT,
            scopes=[
                Scope.DOSSIER_READ,
                Scope.DOCUMENT_READ,
                Scope.DOCUMENT_WRITE,
                Scope.MEDICATION_READ,
                Scope.MEDICATION_WRITE,
            ],
            access_level=Confidentiality.SECRET,
        )
        capability = container.access.mint(db, system_actor, grant=grant)
        db.commit()
        return container.access.authorize(
            db, capability.token, required_scope=Scope.DOSSIER_READ
        )

    def test_documents_above_the_ceiling_are_invisible(
        self, container, db, world, patient_access, doctor_token
    ):
        for level in Confidentiality:
            container.dossiers.add_document(
                db,
                patient_access,
                author=world.patient,
                document=DocumentInput(
                    title=f"{level.value} note",
                    document_class="clinical-note",
                    mime_type="text/plain",
                    content=b"content",
                    confidentiality=level,
                ),
            )
        db.commit()

        doctor_access = container.access.authorize(
            db, doctor_token.token, required_scope=Scope.DOSSIER_READ
        )
        visible = container.dossiers.list_documents(db, doctor_access)
        assert {d.confidentiality for d in visible} == {"normal"}

        all_documents = container.dossiers.list_documents(db, patient_access)
        assert len(all_documents) == 3

    def test_reading_a_hidden_document_is_a_not_found(
        self, container, db, world, patient_access, doctor_token
    ):
        """Distinguishing "forbidden" from "missing" would leak the existence
        of restricted material."""
        secret = container.dossiers.add_document(
            db,
            patient_access,
            author=world.patient,
            document=DocumentInput(
                title="psychotherapy",
                document_class="clinical-note",
                mime_type="text/plain",
                content=b"content",
                confidentiality=Confidentiality.SECRET,
            ),
        )
        db.commit()
        doctor_access = container.access.authorize(
            db, doctor_token.token, required_scope=Scope.DOCUMENT_READ
        )
        from ehealth.services.dossier import DossierError

        with pytest.raises(DossierError, match="unknown document"):
            container.dossiers.read_document(db, doctor_access, secret.uid)

    def test_medication_is_filtered_the_same_way(
        self, container, db, world, patient_access, doctor_token
    ):
        # Both are self-reported: a patient may record their own medication,
        # but not write themselves a prescription — see TestPrescribingAuthority.
        container.medications.record(
            db,
            patient_access,
            StatementInput(
                kind=MedicationEventKind.SELF_REPORTED,
                product_text="Cannabis (medizinisch)",
                confidentiality=Confidentiality.SECRET,
            ),
            recorded_by_uid=world.patient.uid,
        )
        container.medications.record(
            db,
            patient_access,
            StatementInput(
                kind=MedicationEventKind.SELF_REPORTED,
                product_text="Lisinopril 10mg",
            ),
            recorded_by_uid=world.patient.uid,
        )
        db.commit()
        doctor_access = container.access.authorize(
            db, doctor_token.token, required_scope=Scope.MEDICATION_READ
        )
        visible = container.medications.list_for_dossier(db, doctor_access)
        assert [row.product_text for row in visible] == ["Lisinopril 10mg"]
