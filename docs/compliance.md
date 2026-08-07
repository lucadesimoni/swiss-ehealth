# Compliance map

Where each legal requirement lands in the code, and — just as important —
where it does not, so nobody mistakes an intention for an implementation.

## EPDG / LEPD and EPDV (electronic patient record)

| Requirement | Implementation | Test |
|---|---|---|
| Participation is voluntary and revocable (EPDG art. 3) | `Consent.participation`; withdrawal revokes every grant and token in the same transaction | `test_withdrawing_consent_kills_everything_immediately` |
| The AHVN13 is not the record identifier; a sector identifier is derived (EPDG art. 5, EPDV) | `IdentityService` → `ppid` + allocated `spid` (`761.…`); the AHVN13 is discarded or sealed | `test_never_stores_the_ahv_number_in_a_queryable_column` |
| Patient-controlled confidentiality levels (EPDV annex 2) | `Confidentiality` NORMAL / RESTRICTED / SECRET; filtering happens in the query, not after | `TestConfidentialityFiltering` |
| SECRET is visible to the patient alone | clamped in `evaluate_policy`, not merely unassigned | `test_secret_is_clamped_for_third_parties` |
| Emergency access, recorded and notifiable | `Purpose.EMERGENCY`, capped at RESTRICTED, dedicated `access.emergency` event, `notify_patient` flag | `TestEmergency` |
| Patients can see who accessed their record (EPDV art. 17) | `GET /audit/me` over the ledger | `test_patient_grants_a_doctor_who_then_prescribes` step 7 |
| Retention (EPDV art. 10) | `Dossier.retention_until`, 20 years from the last entry, pushed out on every write | `test_opens_with_a_retention_horizon` |
| Institutions identified by CHE-UID, professionals by GLN | `CheUid`, GLN validated as a GTIN-13 | `TestCheUid`, `test_rejects_a_bad_gln` |

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
