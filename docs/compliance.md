# Compliance map

For the path from here to a certified community, see
[`certification.md`](certification.md).

Where each legal requirement lands in the code, and — just as important —
where it does not, so nobody mistakes an intention for an implementation.

## EPDG / LEPD and EPDV (electronic patient record)

| Requirement | Implementation | Test |
|---|---|---|
| Participation is voluntary and revocable (EPDG art. 3) | `Consent.participation`; withdrawal revokes every grant and token in the same transaction | `test_withdrawing_consent_kills_everything_immediately` |
| The AHVN13 is not the record identifier; a sector identifier is derived (EPDG art. 5, EPDV) | `IdentityService` → `ppid` + allocated 18-digit EPR-SPID (`761…`); the AHVN13 is discarded or sealed | `test_never_stores_the_ahv_number_in_a_queryable_column` |
| The EPR-SPID has its own format, distinct from the AHVN13 | 18 digits, prefix 761, mod-10 check digit; a 13-digit value is rejected | `test_a_thirteen_digit_value_is_not_a_spid` |
| Patient-controlled confidentiality levels (EPDV annex 2) | `Confidentiality` NORMAL / RESTRICTED / SECRET; filtering happens in the query, not after | `TestConfidentialityFiltering` |
| SECRET is visible to the patient alone | clamped in `evaluate_policy`, not merely unassigned | `test_secret_is_clamped_for_third_parties` |
| Emergency access, recorded and notifiable | `Purpose.EMERGENCY`, capped at RESTRICTED, dedicated `access.emergency` event, `notify_patient` flag | `TestEmergency` |
| Patients can see who accessed their record (EPDV art. 17) | `GET /audit/me` over the ledger | `test_patient_grants_a_doctor_who_then_prescribes` step 7 |
| Retention (EPDV art. 10) | `Dossier.retention_until`, 20 years from the last entry, pushed out on every write | `test_opens_with_a_retention_horizon` |
| Authentication with a certified identification means at the required level of assurance (EPDV) | Per-provider `accepted_acr` enforced after token verification; `professional_acr` for professionals; production refuses to start without it | `tests/test_login_policy.py` |
| Patient lookups by other systems do not expose the AHVN13, and are audited | PIXm/PDQm refuse the AHVN13 domain, answer professionals only, and log who asked without the search terms | `tests/test_patient_directory.py` |
| Institutions identified by CHE-UID, professionals by GLN | `CheUid`, GLN validated as a GTIN-13 | `TestCheUid`, `test_rejects_a_bad_gln_on_a_credential` |

## Healthcare professionals

The identifiers and authorities Swiss law actually recognises, and where each
one is enforced.

| Requirement | Implementation | Test |
|---|---|---|
| Medical professions are entered in a federal register (MedBG art. 51 ff.) | `ProfessionalRegister.MEDREG` on `ProfessionalCredential` | `TestCredentials` |
| Health professions register (GesBG art. 24 ff.) | `ProfessionalRegister.NAREG` | `test_a_nurse_does_not_prescribe` |
| Psychology professions register (PsyG art. 40 ff.) | `ProfessionalRegister.PSYREG` | — |
| Practice requires a cantonal licence (MedBG art. 34 ff.) | `licence_canton` validated against the 26 cantons, with validity dates and a suspension flag | `test_rejects_an_unknown_canton`, `test_an_expired_licence_does_not` |
| Suspension takes effect immediately | `suspend_credential`; prescribing stops on the next write | `test_a_suspended_licence_stops_prescribing_at_once` |
| Prescribing is tied to profession and licence (HMG art. 24 ff.) | `PRESCRIBING_PROFESSIONS` × live licence, checked in `MedicationService._check_authority` | `TestPrescribingAuthority` |
| A professional is one person, who may also be a patient | roles in `person_role`, one `per_` UID, one pseudonym | `test_a_doctor_can_also_be_a_patient` |
| Billing authority is separate from clinical authority | `zsr_number` recorded but excluded from `may_prescribe` | `test_normalises_the_zsr_number` |
| Provenance of a professional claim | `verified_at` / `verification_source` / evidence, set only by an explicit check | `test_verification_is_recorded_with_its_source` |

The register lookup itself is **not** implemented: MedReg, NAREG, PsyReg and
Refdata each expose their own interface, and none of them belongs inside this
codebase. What belongs here is the evidence that the check happened, which is
what `verify_credential` records.

## Medicinal products

| Requirement | Implementation | Test |
|---|---|---|
| Marketing authorisation (HMG art. 9 ff.) | `swissmedic_authorisation` validated and normalised; `authorisation_status` and expiry | `test_a_withdrawn_product_cannot_be_prescribed` |
| Dispensing categories (HMG art. 23 ff., AMBV) | `DispensingCategory` A/B/D/E — C is absent, having been abolished in 2019, so legacy data fails loudly | `TestPrescribingAuthority` |
| Narcotics (BetmG, BetmVV-EDI) | `NarcoticSchedule` a–d, flagged into every audit entry | `test_the_trail_flags_narcotics_for_a_betmg_audit` |
| Package identification | GTIN with check digit, Refdata Pharmacode, unique per product | `TestSwissProductIdentifiers` |
| Substance classification | ATC validated at every depth | `test_accepts_atc_codes_at_every_depth` |
| Reimbursement (KVG art. 52) | `sl_listed` / `sl_number` | — |
| Responsible company is identifiable | `marketing_authorisation_holder_gln` | — |

Product master data is **not** synchronised from Swissmedic AIPS or Refdata;
the catalogue holds what a deployment loads into it. The identifiers are
validated so that whatever is loaded is at least well formed.

## Revised DSG (Swiss data protection)

| Requirement | Implementation |
|---|---|
| Privacy by design and by default (art. 7) | pseudonymisation is the only way in; safe values are the defaults; enrolment endpoints are off unless a key is configured |
| Data minimisation | the ledger's `detail` never carries clinical content or direct identifiers; diffs reduce protected fields to hashes |
| Right of access (art. 25) | `GET /persons/me`, `GET /audit/me`, `GET /history/{entity}/{uid}` |
| Right to rectification (art. 32) | corrections are supersessions and status changes; the prior version stays in `record_revision` |
| Security of processing (art. 8) | AES-256-GCM field encryption bound to row and column, Ed25519 signatures, HKDF key separation, AAL2 sessions |
| Breach detectability (art. 24) | hash-chained ledger plus anchors: tampering is detectable, not merely unlikely |
| Records of processing (art. 12) | the audit ledger is the processing record, with actor, purpose and legal basis on disclosures |

## AHVG art. 50g — systematic use of the AHVN13

The AHVN13 is accepted at registration, validated, converted into
pseudonyms, and then either discarded or kept only as an AEAD envelope bound to
the pseudonym. It is present in no index, no foreign key, no log line and no
API response. Recovering it requires `disclose_ahvn`, which demands a stated
legal basis and writes its audit entry *before* decrypting, so an aborted
disclosure still leaves a trace.

`Ahvn13.__repr__` returns the masked form, so an accidental f-string in a log
statement cannot leak one.

## GDPR (for cross-border patients)

Art. 15 access, art. 16 rectification, art. 17 erasure (bounded by the
20-year medical retention obligation, which is the art. 17(3)(b) exception),
art. 25 data protection by design, art. 30 records of processing, art. 32
security of processing. The mechanisms are the same ones listed above.

## Authentication

- **OIDC Core + RFC 7636 (PKCE)** — authorisation code flow, server-side state
  and nonce, single-use flows.
- **ID token verification** — signature against the provider JWKS (RS256/384/512,
  ES256/384, EdDSA), issuer, audience, `azp` on multi-audience tokens, expiry,
  issued-at, nonce. Symmetric algorithms are excluded so a leaked client secret
  cannot forge tokens; `none` is not in the accept list at all.
- **RFC 8725 (JWT BCP)** — closed algorithm registry, no `none`, audience and
  issuer bound, key id carries purpose and version, `typ` checked.
- **NIST SP 800-63B** — AAL2 for interactive sessions: a federated identity
  plus an emailed one-time code. A `PENDING_MFA` session carries no authority.

Email OTP is a *second* factor, not a strong one — it inherits the security of
the user's mailbox. It is the pragmatic choice for population-scale rollout.
`OtpChallenge.channel` and the session's assurance level are the seams where a
stronger factor (FIDO2, or SwissID's own step-up) drops in.

## Data sovereignty

- `DataRegion` is an explicit setting, not an implication of a connection
  string.
- One root secret, HSM/KMS-backed in production, with everything else derived
  from it. No key material is shared with any third party.
- No runtime dependency on an external service other than the configured
  identity provider and SMTP relay; `allowed_processor_domains` states which
  hosts a processor may live on.
- The published artifact is self-contained Python — no telemetry, no CDN, no
  managed service call path.

## Crypto agility

`SIGNATURE_ALGORITHMS` is the one place to look when asking "what signs what,
and can we move off it". Ed25519 issues today; ML-DSA-65 (FIPS 204) and a
hybrid Ed25519+ML-DSA are registered and marked unavailable, so a token
claiming them fails closed rather than falling back. Every ciphertext, MAC and
signature carries its algorithm and key version, which is what makes replacing
either a local change rather than a migration.

## Known gaps

Stated so they are decisions rather than oversights:

- **IHE profiles** (XDS.b, PIX/PDQ, CH:ATC) needed to federate with other EPD
  communities are not implemented. The internal model is shaped to map onto
  them.
- **Document storage** is referenced by hash, not implemented.
- **Schema migrations** are not set up; `create_all` covers development only.
- **Notification delivery** for emergency access is decided but not sent.
- **Certification** (EPDG art. 11 requires certified communities) is an
  organisational process this code can support but cannot satisfy on its own.
