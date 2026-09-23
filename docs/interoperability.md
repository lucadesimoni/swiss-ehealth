# Interoperability: the EPD profiles

An EPD community exchanges data with the other communities, and with the
systems of doctors and hospitals, through **IHE profiles** as specified for
Switzerland by eHealth Suisse. A community that doesn't speak them can't join
the national network, however good its internal API is. This document covers
what is implemented and, in more detail, what is not.

## Implemented: patient identity over FHIR

Before anyone can exchange a document about a patient, the systems involved
have to agree on who the patient is. The CH EPR FHIR implementation guide
defines the modern, FHIR-based form of that:

| Profile | Transaction | Endpoint |
|---|---|---|
| **PIXm**: patient identifier cross-reference | ITI-83 | `GET /v1/fhir/Patient/$ihe-pix?sourceIdentifier=urn:oid:…\|…[&targetSystem=urn:oid:…]` |
| **PDQm**: patient demographics query | ITI-78 | `GET /v1/fhir/Patient?identifier=…` or `?family=…&birthdate=…[&given=…][&gender=…]`, and `GET /v1/fhir/Patient/{id}` |
| Capability statement | — | `GET /v1/fhir/metadata` (public) |

Two identifier domains are answered:

| Domain | OID | Value |
|---|---|---|
| EPR-SPID, the national patient identifier of the EPD | `2.16.756.5.30.1.127.3.10.3` | 18 digits |
| This community's patient id (MPI-PID) | `EHEALTH_COMMUNITY_PATIENT_ID_OID` | the person uid (`per_…`) |

The community OID defaults to a placeholder under the ITU example arc
(`2.999…`), and production refuses to start until it is set to the OID
registered for the community.

Errors are FHIR `OperationOutcome`s with the status each profile prescribes.
For PIXm: unknown source domain → 400, unknown target domain → 403, unknown
patient → 404. A patient with no identifier in the requested domain gets an
empty `Parameters` with 200, not an error.

### Privacy decisions in the directory

These are choices about how the directory behaves, not gaps waiting to be
filled.

- **Only healthcare professionals may query.** Every query is audited: who
  asked, which kind of query, and how many patients matched. The search terms
  are *not* recorded, because otherwise the audit trail would become a
  searchable list of names and birthdays.
- **Only patients are found.** People registered only as visitors or
  professionals aren't in the patient directory. The directory answers "not
  found" for them, exactly as for nobody at all.
- **Demographic search needs family name *and* date of birth.** Given name
  and sex narrow the result further. Date ranges are refused. More than
  `EHEALTH_PDQ_MAX_RESULTS` matches (default 10) is refused with
  `too-costly`: this is a lookup of one person, not a list.
- **Names stay encrypted.** The search runs on a keyed blind index over the
  normalised family name and birth date. Normalisation treats `Müller`,
  `Mueller` and `MÜLLER` as one name, and keeps `Muller` separate. After
  upgrading to schema 5, run `make reindex-demographics` once so that people
  registered earlier can be found.
- **The AHVN13 is refused as an identifier domain.** Article 5 of the EPD Act
  (EPDG) keeps the AHV number out of the patient record, and accepting it
  here would allow exactly the cross-referencing the law exists to prevent.

## Not implemented yet

In roughly the order a community needs them:

| Profile | Purpose | Status |
|---|---|---|
| **IUA** (ITI-71/72, CH:ATC extensions) | Access tokens for the FHIR endpoints, carrying the user's role, purpose of use and the patient in the standard form other communities expect | Not implemented. The FHIR endpoints accept this system's own session token for a professional, which other communities cannot issue. |
| **MHD** (ITI-65, 66, 67, 68) | Publishing and retrieving documents over FHIR | Not implemented. There is no document storage yet. |
| **XDS.b / XCA** (ITI-18, 41, 43; ITI-38, 39) | The SOAP-based document exchange the EPD network still runs on between communities | Not implemented. This is the largest single piece of work. |
| **XCPD** (ITI-55) | Finding a patient in *other* communities | Not implemented |
| **PIX V3 / PDQ V3** (ITI-44, 45, 47) | The HL7v3 SOAP forms of the patient-identity transactions, still used between communities | Not implemented. Only the FHIR forms above exist. |
| **ATNA** (ITI-20) | Sending audit records to a central audit repository | Not implemented. The internal audit trail is complete and signed, but is not sent in ATNA form. |
| **CH:ADR / CH:PPQm** | Authorisation decisions and patient privacy policies | Not implemented. Consent is modelled internally. |
| **CH:EMED** | Exchanging medication documents | Not implemented. Medication is modelled internally. |
| **EPR-SPID allocation via the ZAS/CdC UPI service** | Obtaining the official EPR-SPID for a patient | Not implemented. The EPR-SPID is generated locally with the correct format and check digit, but a certified community must obtain it from the central compensation office. |

## Testing conformance

`tests/test_patient_directory.py` checks the shapes and status codes above
against this codebase. It cannot show that another implementation interprets
them the same way. Before certification, a community has to take part in the
**EPD Projectathon** run by eHealth Suisse and pass its test cases against the
reference environment and the other participants. That takes registration,
test certificates and the eHealth Suisse test platform. It can't be done from
this repository, and it is the first real milestone in
[`certification.md`](certification.md).

## References

- CH EPR FHIR implementation guide (eHealth Suisse): <http://fhir.ch/ig/ch-epr-fhir>
- IHE PIXm: <https://profiles.ihe.net/ITI/PIXm/>
- IHE PDQm: <https://profiles.ihe.net/ITI/PDQm/>

The OIDs and profile versions used here should be checked against the
current edition of the CH EPR FHIR guide before the Projectathon. Guides are
revised each year, and a changed value fails a test case without breaking
anything here.
