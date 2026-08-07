"""Request and response models.

Response models never contain an AHV number, and the direct identifiers they
do contain are only populated for callers that passed an access check.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from ehealth.domain.uid import Ahvn13, format_spid
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.clinical import MedicationEventKind
from ehealth.models.core import IdentificationMethod, PersonKind
from ehealth.models.governance import RuleEffect

Ahvn13Str = Annotated[str, Field(examples=["756.1234.5678.97"])]


class StrictModel(BaseModel):
    """Reject unknown fields.

    A silently ignored field in a health API is a silently ignored clinical
    instruction; better a 422 than a dosage that never got applied.
    """

    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------
# Persons
# --------------------------------------------------------------------------


class OrganizationCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    che_uid: str | None = Field(default=None, examples=["CHE-116.281.277"])
    gln: str | None = None
    kind: str = "practice"
    community: str | None = None


class OrganizationOut(BaseModel):
    uid: str
    name: str
    che_uid: str | None
    gln: str | None
    kind: str
    community: str | None
    active: bool


class PersonCreate(StrictModel):
    kind: PersonKind
    given_name: str = Field(min_length=1, max_length=120)
    family_name: str = Field(min_length=1, max_length=120)
    ahvn13: Ahvn13Str | None = None
    birth_date: date | None = None
    administrative_sex: str | None = None
    email: EmailStr | None = None
    phone: str | None = None
    identification_method: IdentificationMethod = IdentificationMethod.AHVN13
    id_document: str | None = None
    gln: str | None = None
    profession: str | None = None
    organization_uid: str | None = None

    @field_validator("ahvn13")
    @classmethod
    def _check_ahvn(cls, value: str | None) -> str | None:
        if value is None:
            return None
        # Parse and discard: this validates format and check digit without
        # letting the raw value linger in a validation error message.
        Ahvn13.parse(value)
        return value


class PersonOut(BaseModel):
    uid: str
    kind: str
    status: str
    spid: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    birth_date: date | None = None
    administrative_sex: str | None = None
    email: str | None = None
    phone: str | None = None
    gln: str | None = None
    profession: str | None = None
    organization_uid: str | None = None
    identification_method: str
    version: int

    @field_validator("spid")
    @classmethod
    def _format(cls, value: str | None) -> str | None:
        return format_spid(value) if value else None


class PersonLookup(StrictModel):
    ahvn13: Ahvn13Str | None = None
    spid: str | None = None


class ContactUpdate(StrictModel):
    email: EmailStr | None = None
    phone: str | None = None
    reason: str | None = Field(default=None, max_length=500)


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


class LoginStartOut(BaseModel):
    authorization_url: str
    state: str


class LoginCallbackIn(StrictModel):
    state: str
    code: str


class LoginChallengeOut(BaseModel):
    session_uid: str
    masked_email: str
    expires_at: datetime
    attempts_remaining: int
    #: Always "otp-email" today; present so a client can branch when stronger
    #: factors are added without changing the response shape.
    second_factor: str = "otp-email"


class OtpVerifyIn(StrictModel):
    session_uid: str
    code: str = Field(min_length=6, max_length=10, pattern=r"^\d+$")


class OtpResendIn(StrictModel):
    session_uid: str


class SessionOut(BaseModel):
    session_uid: str
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_at: datetime
    person_uid: str
    scopes: list[str]


class RefreshIn(StrictModel):
    refresh_token: str


class AccountLinkIn(StrictModel):
    person_uid: str
    issuer: str
    subject: str
    email: EmailStr


# --------------------------------------------------------------------------
# Consent and grants
# --------------------------------------------------------------------------


class ConsentCreate(StrictModel):
    default_access_level: Confidentiality = Confidentiality.NORMAL
    emergency_access_allowed: bool = True
    notify_on_access: bool = False
    evidence: dict[str, Any] = Field(default_factory=dict)


class ConsentUpdate(StrictModel):
    default_access_level: Confidentiality | None = None
    emergency_access_allowed: bool | None = None
    notify_on_access: bool | None = None
    reason: str | None = Field(default=None, max_length=500)


class ConsentOut(BaseModel):
    uid: str
    patient_uid: str
    participation: str
    default_access_level: str
    emergency_access_allowed: bool
    notify_on_access: bool
    version: int


class ConsentRuleCreate(StrictModel):
    subject_type: str = Field(pattern="^(person|organization|group)$")
    subject_uid: str
    effect: RuleEffect
    access_level: Confidentiality = Confidentiality.NORMAL
    valid_until: datetime | None = None
    note: str | None = Field(default=None, max_length=500)


class ConsentRuleOut(BaseModel):
    uid: str
    subject_type: str
    subject_uid: str
    effect: str
    access_level: str
    valid_from: datetime | None
    valid_until: datetime | None


class GrantCreate(StrictModel):
    dossier_uid: str
    grantee_uid: str
    purpose: Purpose = Purpose.TREATMENT
    scopes: list[str] = Field(min_length=1)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86_400)
    access_level: Confidentiality | None = None
    max_uses: int = Field(default=0, ge=0, le=1000)
    note: str | None = Field(default=None, max_length=500)


class VisitorGrantCreate(StrictModel):
    """A patient handing time-boxed read access to a visitor."""

    visitor_uid: str
    scopes: list[str] = Field(
        default_factory=lambda: ["dossier:read", "medication:read"]
    )
    ttl_seconds: int = Field(default=4 * 3600, ge=300, le=86_400)
    max_uses: int = Field(default=20, ge=1, le=1000)
    note: str | None = Field(default=None, max_length=500)


class GrantOut(BaseModel):
    uid: str
    dossier_uid: str
    grantee_uid: str
    grantee_kind: str
    purpose: str
    access_level: str
    scopes: list[str]
    valid_from: datetime
    valid_until: datetime
    status: str
    max_uses: int
    use_count: int


class CapabilityOut(BaseModel):
    token: str
    jti: str
    grant_uid: str
    expires_at: datetime
    scopes: list[str]
    access_level: str


class EmergencyAccessIn(StrictModel):
    patient_uid: str
    justification: str = Field(min_length=10, max_length=500)


class RevokeIn(StrictModel):
    reason: str = Field(min_length=3, max_length=500)


# --------------------------------------------------------------------------
# Dossier and documents
# --------------------------------------------------------------------------


class DossierCreate(StrictModel):
    patient_uid: str
    home_community: str | None = None
    default_confidentiality: Confidentiality = Confidentiality.NORMAL


class DossierOut(BaseModel):
    uid: str
    patient_uid: str
    status: str
    opened_at: datetime
    retention_until: datetime | None
    default_confidentiality: str
    home_community: str | None
    version: int


class DocumentCreate(StrictModel):
    title: str = Field(min_length=1, max_length=300)
    document_class: str = Field(min_length=1, max_length=80)
    mime_type: str = "application/pdf"
    #: base64 payload. Real deployments stream to object storage instead; the
    #: hash recorded here is what makes that storage untrusted-by-default.
    content_base64: str
    confidentiality: Confidentiality = Confidentiality.NORMAL
    language: str = "de-CH"
    supersedes_uid: str | None = None
    service_start: datetime | None = None
    service_end: datetime | None = None


class DocumentOut(BaseModel):
    uid: str
    dossier_uid: str
    title: str
    document_class: str
    mime_type: str
    language: str
    confidentiality: str
    status: str
    author_uid: str
    author_organization_uid: str | None
    content_hash: str
    content_size: int
    created_at: datetime
    version: int


# --------------------------------------------------------------------------
# Medication
# --------------------------------------------------------------------------


class ProductCreate(StrictModel):
    gtin: str = Field(min_length=8, max_length=14, pattern=r"^\d+$")
    name: str = Field(min_length=1, max_length=240)
    swissmedic_authorisation: str | None = None
    active_ingredient: str | None = None
    atc_code: str | None = Field(default=None, max_length=12)
    dose_form: str | None = None
    strength: str | None = None
    package_size: str | None = None
    marketing_authorisation_holder: str | None = None
    narcotic: bool = False
    prescription_only: bool = True


class ProductOut(BaseModel):
    uid: str
    gtin: str
    name: str
    swissmedic_authorisation: str | None
    active_ingredient: str | None
    atc_code: str | None
    dose_form: str | None
    strength: str | None
    package_size: str | None
    narcotic: bool
    prescription_only: bool
    version: int


class MedicationCreate(StrictModel):
    kind: MedicationEventKind
    product_uid: str | None = None
    product_text: str | None = Field(default=None, max_length=240)
    dosage: dict[str, Any] = Field(default_factory=dict)
    quantity: str | None = None
    reason: str | None = None
    effective_start: datetime | None = None
    effective_end: datetime | None = None
    confidentiality: Confidentiality = Confidentiality.NORMAL
    based_on_uid: str | None = None


class MedicationOut(BaseModel):
    uid: str
    dossier_uid: str
    kind: str
    status: str
    confidentiality: str
    product_uid: str | None
    product_text: str | None
    dosage: dict[str, Any]
    quantity: str | None
    reason: str | None
    effective_start: datetime | None
    effective_end: datetime | None
    recorded_by_uid: str
    organization_uid: str | None
    based_on_uid: str | None
    version: int


class DosageUpdate(StrictModel):
    dosage: dict[str, Any]
    reason: str = Field(min_length=3, max_length=500)


class StopMedicationIn(StrictModel):
    reason: str = Field(min_length=3, max_length=500)
    effective_end: datetime | None = None


# --------------------------------------------------------------------------
# Audit and history
# --------------------------------------------------------------------------


class AuditEventOut(BaseModel):
    seq: int
    uid: str
    occurred_at: datetime
    actor_uid: str | None
    actor_kind: str
    on_behalf_of_uid: str | None
    action: str
    outcome: str
    purpose: str | None
    resource_type: str
    resource_uid: str | None
    dossier_uid: str | None
    token_jti: str | None
    detail: dict[str, Any]
    entry_hash: str


class ChainVerificationOut(BaseModel):
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


class RevisionOut(BaseModel):
    uid: str
    entity_type: str
    entity_uid: str
    version: int
    operation: str
    changed_by_uid: str | None
    changed_at: datetime
    valid_from: datetime
    valid_until: datetime | None
    diff: dict[str, Any]
    state_hash: str
    audit_seq: int | None
    reason: str | None
