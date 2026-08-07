# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Importing this package registers every table on the metadata."""

from ehealth.models.audit import (
    AuditAction,
    AuditEvent,
    AuditOutcome,
    ChangeOperation,
    LedgerAnchor,
    RecordRevision,
)
from ehealth.models.auth import (
    AccountStatus,
    AssuranceLevel,
    AuthSession,
    IdentityAccount,
    OidcFlow,
    OtpChallenge,
    SessionState,
)
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.clinical import (
    DocumentStatus,
    Dossier,
    DossierDocument,
    DossierStatus,
    MedicationEventKind,
    MedicationStatement,
    MedicationStatus,
    MedicinalProduct,
)
from ehealth.models.core import (
    IdentificationMethod,
    Organization,
    Person,
    PersonKind,
    PersonStatus,
)
from ehealth.models.governance import (
    AccessGrant,
    Consent,
    ConsentRule,
    GrantStatus,
    IssuedToken,
    ParticipationStatus,
    RuleEffect,
    TokenKind,
)

__all__ = [
    "AccessGrant",
    "AccountStatus",
    "AssuranceLevel",
    "AuditAction",
    "AuditEvent",
    "AuditOutcome",
    "AuthSession",
    "ChangeOperation",
    "Confidentiality",
    "Consent",
    "ConsentRule",
    "DocumentStatus",
    "Dossier",
    "DossierDocument",
    "DossierStatus",
    "GrantStatus",
    "IdentificationMethod",
    "IdentityAccount",
    "IssuedToken",
    "LedgerAnchor",
    "MedicationEventKind",
    "MedicationStatement",
    "MedicationStatus",
    "MedicinalProduct",
    "OidcFlow",
    "Organization",
    "OtpChallenge",
    "Person",
    "PersonKind",
    "PersonStatus",
    "ParticipationStatus",
    "Purpose",
    "RecordRevision",
    "RuleEffect",
    "SessionState",
    "TokenKind",
]
