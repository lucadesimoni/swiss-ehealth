# Roadmap

What stands between this codebase and holding real patients' health data in
Switzerland, in the order it is needed.

**Status (October 2026): not ready for real patient data.** The technical base
is in place: storage, access control, a tamper-evident audit trail, and the
national FHIR interfaces. Under the EPD Act, though, the *operator* is
certified, not the software, and most of the remaining work is
organisational. Use demo data only until the items marked **blocking** below
are done.

Effort is a rough estimate in person-weeks for an experienced developer, to
help with planning. It is not a quote. This is a technical plan, not legal
advice; a certification body's pre-assessment gives the binding answer.

## Already done

| Area | Where |
|---|---|
| Encrypted storage of documents and identifying data, separate keys per purpose; the AHV number never stored in a searchable form | `services/blobstore.py`, `domain/identity.py` |
| Signed, hash-chained audit trail per patient; the patient reads their own trail (CH:ATC) | `services/audit.py`, `api/routes_atc.py` |
| Access decided by the patient's consent, checked again on every request; confidentiality levels enforced inside the database query | `services/access.py` |
| Login through SwissID / HIN / AGOV, with two factors and a minimum level of assurance per provider | `services/auth.py`, `docs/identity-providers.md` |
| 20-year retention and the purge job | `services/retention.py` |
| PIXm, PDQm with `$match`, MHD (ITI-65/67/68), CH:ATC, IUA (ITI-71/72/103), per CH EPR FHIR v5.0.0 | `docs/interoperability.md` |
| Restore rehearsal, load test, hash-pinned dependencies, SBOM, run in CI on every push | `.github/workflows/ci.yml` |

## 1. Software

### Blocking: needed to join the national network

| # | Item | Why | Effort |
|---|---|---|---|
| S1 | **XDS.b / XCA** (ITI-18, 41, 43; ITI-38, 39) | Communities still exchange documents with each other over these SOAP profiles. The largest single piece of work. | 12–20 |
| S2 | **XCPD** (ITI-55) | Finding a patient in other communities | 4–6 |
| S3 | **PIX V3 / PDQ V3** (ITI-44, 45, 47) | The SOAP forms of patient identification, for partners not yet on FHIR | 4–6 |
| S4 | **ATNA** (ITI-20) | Audit records sent in the standard form to a central audit repository. The content already exists; this is format and transport. | 2–3 |
| S5 | **EPR-SPID from the UPI service** (ZAS/CdC) | A certified community must obtain the official number, not generate it locally. Needs a contract and certificates (see O5). | 2–4 |
| S6 | **XUA / SAML assertions** | Cross-community calls carry the user's identity as SAML | 4–6 |

### Needed for certification and day-to-day use

| # | Item | Why | Effort |
|---|---|---|---|
| S7 | **Notifications** for emergency access and for "notify me on access" | The patient is flagged for notification today, but no message is sent | 1–2 |
| S8 | **Representative and assistant roles** (REP, ASS), in IUA and in the access model | Legal representatives and practice assistants are part of the EPD role model | 3–4 |
| S9 | **Tokens from other communities' IUA servers** | Their keys, and a mapping from their users to local accounts | 2–3 |
| S10 | **CH:ADR / CH:PPQm** | Authorisation decisions and patient privacy policies in the standard form. Consent is already modelled internally. | 4–6 |
| S11 | **Patients' data rights**: a complete, machine-readable export of their own record, and a way for patients to *request* a correction | Revised DSG (access, portability, correction). The offline bundle is a partial copy, and authors can already correct documents by superseding them. | 2–3 |
| S12 | **Backups and monitoring as code**: scheduled encrypted backups, alerting, integrity check of the audit trail on a schedule | The restore is rehearsed in CI, but nothing yet runs it on a schedule in an operated system | 2–3 |

### Later

| # | Item | Effort |
|---|---|---|
| S13 | **CH:EMED** medication documents (medication is modelled internally) | 6–10 |
| S14 | MHD **ITI-66** and metadata update (ITI-105/106) | 2 |
| S15 | `traceparent` handling (CH EPR FHIR appendix "Trace Context") | < 1 |
| S16 | S3-compatible document storage on a Swiss provider | 1 |
| S17 | Signed container images, reproducible builds, base image pinned by digest | 1–2 |
| S18 | Logout at the identity provider (RP-initiated logout); passkeys | 1–2 |
| S19 | Post-quantum signatures (ML-DSA-65) once a vetted library is available; the algorithm registry is ready for it | 2 |

## 2. Independent proof (blocking)

Nothing above counts until someone outside the project has checked it.

| # | Item | Notes |
|---|---|---|
| P1 | **External penetration test**, with every finding tracked to closure | Before any real data |
| P2 | **Independent code and architecture review** | Especially access control, cryptography and the audit trail |
| P3 | **Identity-provider integration tests** against the SwissID, HIN and AGOV integration environments | Checklist in `docs/identity-providers.md`; needs registered test clients |
| P4 | **eHealth Suisse Projectathon 2027** | Register when the call opens; test PIXm/PDQm, MHD, CH:ATC, IUA and AGOV login |

## 3. Organisation (blocking, and not code)

| # | Item | Notes |
|---|---|---|
| O1 | **Choose the path**: certified community until the E-GD arrives, component of the federal E-GD infrastructure, or a system that connects to it | `docs/certification.md`, "The law is changing". The E-GD is expected around 2030. |
| O2 | **A Swiss legal entity** as operator and copyright holder, with written governance | `docs/sovereignty.md` |
| O3 | **Security management system** modelled on ISO/IEC 27001: risk analysis, policies, incident response, business continuity | Takes longer than the code |
| O4 | **Data protection** under the revised DSG: impact assessment (DSFA), record of processing activities, data protection officer, patient information and consent forms | |
| O5 | **Registrations and contracts**: community OID, UPI access, hosting in Switzerland, identity providers | Each needs a contract and a lead time |
| O6 | **Patient onboarding** with identity verification by trained staff, including legal representatives | EPDV |
| O7 | **Certification body**: choose one accredited by SAS and book a pre-assessment against this list | |

## Order

The three tracks run in parallel. What blocks what:

| When | Software | Proof | Organisation |
|---|---|---|---|
| Months 0–3 | S7, S11, S12, S15 | P3 | O1, O2, O7 (pre-assessment) |
| Months 3–9 | S1–S6, S8, S9 | P2 | O3, O4, O5 |
| Months 9–12 | S10, S14, S17 | P1, P4 | O6 |
| Months 12–18 | Findings from P1/P2 | | Certification audit |

Twelve to twenty-four months from today to a certificate is realistic. Most
of that time goes to the organisational work and to other parties'
calendars, not to coding.
