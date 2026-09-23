# Certification as a project

A plan for taking this codebase to a certified EPD community. It sets out
what certification involves, what this repository already covers, what it
can't cover, and an order in which to do the rest.

**Read this first.** Under the Swiss EPD Act (EPDG) it is not software that
gets certified. It is the **community** (*Gemeinschaft*) or **reference
community** (*Stammgemeinschaft*), the organisation that operates the patient
record. Certification means the organisation shows an accredited
certification body that its technology, security, data protection and
processes meet the federal requirements. This codebase can supply much of the
technical evidence. It can't supply the organisation, and roughly half of the
work is organisational.

> This document is a planning aid, not legal advice. The requirements are set
> by the EPD Act, the EPD ordinance (EPDV), the ordinance of the Federal
> Department of Home Affairs (EPDV-EDI) with its annexes, and the
> implementation guides of eHealth Suisse. All of them are revised
> periodically, and the EPD Act itself is under a major revision. Plan
> against the current texts and involve the certification body early.

## The framework, briefly

| Source | What it sets |
|---|---|
| **EPDG** (SR 816.1) | Who may operate a community, patients' rights, voluntary participation, the EPR-SPID |
| **EPDV** (SR 816.11) | Certification procedure, identification of patients, retention, access rights, audit trails patients can read |
| **EPDV-EDI** (SR 816.111) and annexes | The *technical and organisational certification requirements* (TOZ), the metadata, and the exchange formats and IHE profiles |
| **eHealth Suisse** guides | The Swiss IHE profiles, CH EPR FHIR, and the annual **Projectathon** |
| **Revised DSG** (Swiss data protection law) | Privacy by design, the data-protection impact assessment (DSFA), the record of processing activities |
| **Certification body** | Accredited by the Swiss Accreditation Service (SAS) for EPD certification. It carries out the audit and issues the certificate. |

Identification means (SwissID, HIN and so on) are certified **separately**,
by their own issuers. A community relies on certified identification means;
it doesn't certify its login provider itself (see
[`identity-providers.md`](identity-providers.md)).

## What this repository already covers

Each row names where the evidence lives. A certification body will want to
see the evidence, not just the claim.

| Area | Covered here | Evidence |
|---|---|---|
| The AHVN13 kept out of the record, the EPR-SPID as the record identifier | Yes. The AHVN13 is never stored in a queryable column, and the PIXm/PDQm interfaces refuse it. | `docs/compliance.md`, `test_never_stores_the_ahv_number_in_a_queryable_column`, `test_the_ahvn13_is_refused_as_an_identifier` |
| Confidentiality levels, SECRET visible to the patient only | Yes | `TestConfidentialityFiltering`, `test_secret_is_clamped_for_third_parties` |
| Voluntary, revocable participation | Yes | `test_withdrawing_consent_kills_everything_immediately` |
| Emergency access, recorded and notifiable | Recorded yes; notification transport no | `TestEmergency` |
| Patients can see who accessed their record | Yes (`GET /audit/me`) | end-to-end test, step 7 |
| Tamper-evident, verifiable audit trail | Yes: signed hash chains, anchors, verification endpoint | `tests/test_audit_ledger.py` |
| 20-year retention horizon | Modelled (`retention_until`); deletion jobs not built | `test_opens_with_a_retention_horizon` |
| Authentication at a required level of assurance, two factors | Yes, per provider. Production refuses to start without it. | `tests/test_login_policy.py`, `tests/test_oidc_provider.py` |
| Professionals identified by GLN and register, licence checked on every write | Yes. The register lookups themselves are not built. | `TestPrescribingAuthority`, `TestCredentials` |
| Encryption of direct identifiers, keys by purpose and version | Yes | `tests/test_crypto_and_identity.py` |
| Hosting in Switzerland, no foreign processors | Configuration enforced (`data_region`, `allowed_processor_domains`) | `docs/deployment-ch.md` |
| Traceable releases: which code wrote which record | Yes: signed build label on every audit entry, and the release and component ledgers | `docs/versioning.md` |
| Schema changes that can't silently corrupt data | Yes: migrations, a boot guard in both directions, a drift check, all run on PostgreSQL in CI | `docs/migrations.md` |
| Patient identity for other systems (PIXm, PDQm) | Yes, over FHIR | `docs/interoperability.md` |

## What this repository cannot cover

These gaps can't be closed by writing code in this repository. Each needs an
organisation, a contract, an external party, or all three.

1. **The operating organisation.** Its legal form, governance, and contracts
   with the healthcare institutions that join it, plus named people: a data
   protection officer, a security officer, and those responsible for
   operations and support.
2. **An information security management system (ISMS)**, in practice modelled
   on ISO/IEC 27001: risk analysis, security concept, policies,
   supplier management, incident management, business continuity. The code
   supplies controls; the ISMS decides, documents and reviews them.
3. **The data-protection impact assessment** (DSFA, revised DSG art. 22), the
   record of processing activities, the patient information texts and the
   consent forms.
4. **Patient onboarding.** Opening a record requires verifying the patient's
   identity in the way the EPDV prescribes, which is a counter or video
   process run by people. It also needs a procedure for legal
   representatives.
5. **Connection to the national services**, above all EPR-SPID allocation
   through the central compensation office (ZAS/CdC UPI service), plus the
   central reference services every community uses. Each needs registration,
   certificates and contracts.
6. **The Projectathon** run by eHealth Suisse, where interoperability is
   tested against the reference environment and the other communities. It
   runs on a fixed calendar, and missing one costs months.
7. **External security testing**: a penetration test and a code review by an
   independent party, with findings tracked to closure.
8. **Operations proven in practice**: backups whose restore has been
   rehearsed, monitoring, on-call, and incident response that has actually
   been exercised.

## The remaining technical work, in order

From [`interoperability.md`](interoperability.md), ordered by what blocks
what:

| # | Work | Why it comes here |
|---|---|---|
| 1 | **IUA** access tokens (ITI-71/72, CH:ATC) | Every other profile is authorised with them. Without them no other community can call these endpoints. |
| 2 | **Document storage**, then **MHD** (ITI-65/66/67/68) | Nothing can be exchanged until documents can be stored. |
| 3 | **XDS.b / XCA** (ITI-18/41/43, ITI-38/39) and **XCPD** (ITI-55) | Communities still exchange with each other this way. It's the largest single piece of work. |
| 4 | **PIX V3 / PDQ V3** (ITI-44/45/47) | The SOAP forms of the patient-identity transactions, for partners not yet on FHIR |
| 5 | **ATNA** (ITI-20) | Audit records in the standard form. The internal trail already holds the content, so this is a matter of transport and format. |
| 6 | **CH:ADR / CH:PPQm** | Authorisation decisions and patient privacy policies in the standard form. Consent is already modelled internally. |
| 7 | **CH:EMED** | Medication documents. Medication is already modelled internally. |
| 8 | **UPI client** for the EPR-SPID | Replaces local generation. The allocation loop already has the right shape for it. |
| 9 | **Retention jobs, notification transport, SAML** where a provider requires it | Needed for completeness, not for exchange |

## A realistic plan

Twelve to twenty-four months is typical from a working system to a
certificate, and most of that time goes to the organisational work and the
external parties' calendars, not to coding. The phases overlap.

| Phase | Months | Outcome | Milestone |
|---|---|---|---|
| **0 · Decide** | 0–2 | Who operates the community and with which partners; budget; who is responsible for each area | Operating organisation founded, roles named |
| **1 · Gap analysis** | 1–3 | This document, checked against the current TOZ, *together with the certification body* in a pre-assessment | Signed-off gap list |
| **2 · Build** | 2–12 | Technical work items 1–5 above; ISMS and DSFA started in parallel | MHD and XDS.b working in the eHealth Suisse test environment |
| **3 · Projectathon** | at the next date | Test cases passed against the reference environment and other participants | Projectathon results report |
| **4 · Prove operations** | 9–15 | Pen test and findings closed; restore rehearsed; incidents exercised; onboarding process trialled | Evidence folder complete |
| **5 · Certification audit** | 12–18 | Document review and on-site audit by the certification body | Certificate |
| **6 · Keep it** | ongoing | Annual surveillance audits, recertification, the yearly guide revisions and Projectathons | — |

## The evidence folder

A certification audit goes much more smoothly when this folder exists before
the auditor asks for it. Start it now. Much of it can already be produced
from this repository.

- The **compliance map** ([`compliance.md`](compliance.md)), linking each
  requirement to code and test, kept current with each release
- **CI records** for the certified release: the suite on PostgreSQL, the image
  build, the commit (see `RELEASES.json` and the per-component ledger)
- **Identity-provider test reports**, per provider, from the checklist in
  [`identity-providers.md`](identity-providers.md)
- **Projectathon results**
- **Penetration test report**, with each finding's resolution
- **ISMS documents**: risk analysis, security concept, policies,
  supplier list with contracts showing hosting in Switzerland
- **DSFA** and the record of processing activities
- **Operations records**: restore rehearsals, incident exercises, change
  management (the release ledger already records what shipped and when)
- **Onboarding procedure** and training records for the staff who verify
  patient identities

## First steps that don't wait for anything

1. Name the operating organisation and a person accountable for
   certification.
2. Contact eHealth Suisse: current TOZ version, Projectathon dates, test
   environment access.
3. Choose a certification body accredited by SAS and book a pre-assessment
   against this gap list.
4. Register test clients with SwissID and HIN and work through the checklist
   in [`identity-providers.md`](identity-providers.md).
5. Apply for the OID of the community's patient-identifier domain and set
   `EHEALTH_COMMUNITY_PATIENT_ID_OID`.
6. Start the ISMS risk analysis and the DSFA. Both take longer than the code.
