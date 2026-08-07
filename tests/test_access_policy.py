# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The consent decision, as a pure function.

These cases are the actual privacy policy of the system, written out. They run
without a database on purpose: the rules should be checkable by someone who
does not read SQLAlchemy.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from ehealth.db import utcnow
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.core import PersonKind
from ehealth.models.governance import ParticipationStatus, RuleEffect
from ehealth.services.access import (
    EMERGENCY_CEILING,
    ConsentSnapshot,
    RuleSnapshot,
    evaluate_policy,
)

PATIENT = "pat_01J8Z3K7QF9M2C4V6X8B0N5RTD"
DOCTOR = "hcp_01J8Z3K7QF9M2C4V6X8B0N5RTE"
OTHER_DOCTOR = "hcp_01J8Z3K7QF9M2C4V6X8B0N5RTF"
HOSPITAL = "org_01J8Z3K7QF9M2C4V6X8B0N5RTG"
VISITOR = "vis_01J8Z3K7QF9M2C4V6X8B0N5RTH"


def consent(**overrides) -> ConsentSnapshot:
    defaults = dict(
        patient_uid=PATIENT,
        participation=ParticipationStatus.ACTIVE,
        default_access_level=Confidentiality.NORMAL,
        emergency_access_allowed=True,
    )
    defaults.update(overrides)
    return ConsentSnapshot(**defaults)


def decide(snapshot, **overrides):
    defaults = dict(
        requester_uid=DOCTOR,
        requester_kind=PersonKind.HEALTHCARE_PROFESSIONAL,
        organization_uid=HOSPITAL,
        purpose=Purpose.TREATMENT,
    )
    defaults.update(overrides)
    return evaluate_policy(snapshot, **defaults)


class TestPatientsOwnAccess:
    def test_patient_reaches_every_level_of_their_own_record(self):
        decision = decide(
            consent(), requester_uid=PATIENT, purpose=Purpose.PATIENT_ACCESS,
            requester_kind=PersonKind.PATIENT,
        )
        assert decision.allowed
        assert decision.max_level is Confidentiality.SECRET

    def test_patient_keeps_access_after_withdrawing(self):
        """Withdrawal removes *others'* access. Locking a patient out of their
        own record would be a new harm, not a privacy protection."""
        decision = decide(
            consent(participation=ParticipationStatus.WITHDRAWN),
            requester_uid=PATIENT,
            requester_kind=PersonKind.PATIENT,
            purpose=Purpose.PATIENT_ACCESS,
        )
        assert decision.allowed
        assert decision.max_level is Confidentiality.SECRET

    def test_a_representative_acts_with_the_same_reach(self):
        decision = decide(
            consent(),
            requester_uid=PATIENT,
            requester_kind=PersonKind.REPRESENTATIVE,
            purpose=Purpose.REPRESENTATIVE,
        )
        assert decision.allowed


class TestParticipation:
    @pytest.mark.parametrize(
        "status", [ParticipationStatus.WITHDRAWN, ParticipationStatus.SUSPENDED]
    )
    def test_no_third_party_access_without_active_participation(self, status):
        decision = decide(consent(participation=status))
        assert not decision.allowed
        assert status.value in decision.reason


class TestDefaultLevel:
    def test_uses_the_patients_default(self):
        decision = decide(consent(default_access_level=Confidentiality.RESTRICTED))
        assert decision.allowed
        assert decision.max_level is Confidentiality.RESTRICTED

    def test_secret_is_clamped_for_third_parties(self):
        """SECRET means "patient only". A default that tried to hand it to
        professionals is capped rather than honoured, so the level keeps its
        promise."""
        decision = decide(consent(default_access_level=Confidentiality.SECRET))
        assert decision.max_level is Confidentiality.RESTRICTED


class TestRules:
    def test_an_allow_rule_raises_the_level(self):
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot(
                        "person", DOCTOR, RuleEffect.ALLOW, Confidentiality.RESTRICTED
                    ),
                )
            )
        )
        assert decision.max_level is Confidentiality.RESTRICTED
        assert decision.matched_rules == (f"allow:{DOCTOR}",)

    def test_a_deny_rule_wins_over_an_allow(self):
        """Specificity must not matter here: an exclusion the patient made
        explicitly can never be overridden by a broader permission."""
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot(
                        "person", DOCTOR, RuleEffect.ALLOW, Confidentiality.RESTRICTED
                    ),
                    RuleSnapshot(
                        "organization", HOSPITAL, RuleEffect.DENY, Confidentiality.NORMAL
                    ),
                )
            )
        )
        assert not decision.allowed
        assert "exclusion" in decision.reason

    def test_a_rule_for_someone_else_does_not_apply(self):
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot("person", OTHER_DOCTOR, RuleEffect.DENY, Confidentiality.NORMAL),
                )
            )
        )
        assert decision.allowed

    def test_an_organization_rule_matches_the_requesters_institution(self):
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot(
                        "organization", HOSPITAL, RuleEffect.ALLOW, Confidentiality.RESTRICTED
                    ),
                )
            )
        )
        assert decision.max_level is Confidentiality.RESTRICTED

    def test_an_expired_rule_is_ignored(self):
        past = utcnow() - timedelta(days=1)
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot(
                        "person",
                        DOCTOR,
                        RuleEffect.DENY,
                        Confidentiality.NORMAL,
                        valid_until=past,
                    ),
                )
            )
        )
        assert decision.allowed

    def test_a_future_rule_is_not_yet_in_force(self):
        future = utcnow() + timedelta(days=1)
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot(
                        "person",
                        DOCTOR,
                        RuleEffect.DENY,
                        Confidentiality.NORMAL,
                        valid_from=future,
                    ),
                )
            )
        )
        assert decision.allowed

    def test_the_highest_allow_rule_wins(self):
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot("person", DOCTOR, RuleEffect.ALLOW, Confidentiality.NORMAL),
                    RuleSnapshot(
                        "organization", HOSPITAL, RuleEffect.ALLOW, Confidentiality.RESTRICTED
                    ),
                )
            )
        )
        assert decision.max_level is Confidentiality.RESTRICTED


class TestEmergency:
    def test_break_glass_bypasses_rules_but_not_the_ceiling(self):
        decision = decide(
            consent(
                rules=(
                    RuleSnapshot("person", DOCTOR, RuleEffect.DENY, Confidentiality.NORMAL),
                )
            ),
            purpose=Purpose.EMERGENCY,
        )
        assert decision.allowed
        assert decision.max_level is EMERGENCY_CEILING
        assert decision.max_level is not Confidentiality.SECRET

    def test_always_flags_the_patient_for_notification(self):
        """Break-glass that leaves no trace is a backdoor, not break-glass."""
        assert decide(consent(), purpose=Purpose.EMERGENCY).notify_patient

    def test_respects_a_patient_who_disabled_it(self):
        decision = decide(
            consent(emergency_access_allowed=False), purpose=Purpose.EMERGENCY
        )
        assert not decision.allowed

    def test_is_refused_when_participation_ended(self):
        decision = decide(
            consent(participation=ParticipationStatus.WITHDRAWN),
            purpose=Purpose.EMERGENCY,
        )
        assert not decision.allowed


class TestPurposeAndKind:
    @pytest.mark.parametrize(
        "purpose", [Purpose.ADMINISTRATION, Purpose.PATIENT_ACCESS, Purpose.REPRESENTATIVE]
    )
    def test_a_third_party_cannot_use_a_patient_only_purpose(self, purpose):
        decision = decide(consent(), purpose=purpose)
        assert not decision.allowed

    def test_quality_assurance_is_permitted(self):
        assert decide(consent(), purpose=Purpose.QUALITY_ASSURANCE).allowed

    def test_a_visitor_never_gets_in_through_consent_alone(self):
        """Visitor access must come from an explicit, time-boxed grant."""
        decision = decide(
            consent(), requester_uid=VISITOR, requester_kind=PersonKind.VISITOR
        )
        assert not decision.allowed
        assert "explicit grant" in decision.reason


class TestNotification:
    def test_honours_notify_on_access(self):
        assert decide(consent(notify_on_access=True)).notify_patient
        assert not decide(consent(notify_on_access=False)).notify_patient
