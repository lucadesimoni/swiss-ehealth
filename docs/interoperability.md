# Interoperability: the EPD profiles

An EPD community exchanges data with the other communities, and with the
systems of doctors and hospitals, through **IHE profiles** as specified for
Switzerland by eHealth Suisse. A community that doesn't speak them can't join
the national network, however good its internal API is. This document covers
what is implemented and, in more detail, what is not.

**Implementation guide version.** Checked against **CH EPR FHIR v5.0.0**
(generated 2026-01-30), which uses PIXm and PDQm with `$match` for patient
identification, requires IUA on MHD, and references patients by EPR-SPID. The
guide is revised each year (HL7 CH ballot); recheck before each Projectathon.

## Implemented: patient identity over FHIR

Before anyone can exchange a document about a patient, the systems involved
have to agree on who the patient is. The CH EPR FHIR implementation guide
defines the modern, FHIR-based form of that:

| Profile | Transaction | Endpoint |
|---|---|---|
| **PIXm**: patient identifier cross-reference | ITI-83 | `GET /v1/fhir/Patient/$ihe-pix?sourceIdentifier=urn:oid:…\|…[&targetSystem=urn:oid:…]` |
| **PDQm `$match`**: patient demographics match, the form v5.0.0 selects | ITI-119 | `POST /v1/fhir/Patient/$match` with `Parameters(resource=Patient, onlyCertainMatches, count)`. Each answer carries `search.score` and a match grade. *certain* only for a known identifier, never for demographics alone. |
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

## Implemented: documents over FHIR (MHD)

| Transaction | Endpoint |
|---|---|
| **ITI-65** Provide Document Bundle | `POST /v1/fhir` with a `transaction` Bundle: one SubmissionSet `List`, one or more `DocumentReference`, and the `Binary` each points to |
| **ITI-67** Find Document References | `GET /v1/fhir/DocumentReference?patient.identifier=urn:oid:…\|…[&status=current,superseded,entered-in-error]`, and `GET /v1/fhir/DocumentReference/{id}` |
| **ITI-68** Retrieve Document | `GET /v1/fhir/Binary/{id}`, the URL in each attachment |

Access takes an **IUA extended access token** for *that patient's* record
(below), or this system's own capability. A token for one patient's record
can't be pointed at another patient by changing the identifier in the query
or the bundle. The EPD
confidentiality levels are applied inside the database query: a document
above the caller's level is not returned, counted, or retrievable by id. Each
document must carry a CH EPR confidentiality code (SNOMED CT 17621005 /
263856008 / 1141000195107); one without a code is refused, rather than filed
at the most visible level by default.

Contents are encrypted with AES-256-GCM before they reach storage, tied to
the document's id, and checked against the SHA-256 recorded at write time on
every read. Storage is treated as untrusted: see `services/blobstore.py`.
Production requires `EHEALTH_DOCUMENT_STORE_PATH`.

## Implemented: IUA access tokens

CH EPR FHIR v5.0.0 authorises MHD, PIXm/PDQm and CH:ATC with **IUA** access
tokens. This system is both the **Authorization Server** that issues them and
the **Resource Server** that checks them.

| Transaction | Endpoint |
|---|---|
| **ITI-103** Get Authorization Server Metadata | `GET /v1/fhir/.well-known/smart-configuration` (public). The CapabilityStatement points to it too. |
| **ITI-71** Get Access Token: authorisation request | `GET /v1/iua/authorize` (code flow, PKCE S256 required) |
| **ITI-71** Get Access Token: token request | `POST /v1/iua/token`, form-encoded, **signed** (RFC 9421) |
| **ITI-72** Incorporate Access Token | `Authorization: Bearer <token>` on every FHIR endpoint |
| Token signing key | `GET /v1/iua/jwks.json` |

### Getting a token

| Option (guide) | Grant | Who identifies the user |
|---|---|---|
| **Technical User** | `client_credentials`, scope `purpose_of_use=…\|AUTO subject_role=…\|TCU`, `principal_id` = GLN | Nobody: the archive writes on behalf of the professional registered for it at onboarding. Any other `principal_id` is refused. |
| **Workflow Initiator**, user signed in here | `authorization_code` | This system's own login session (SwissID/HIN/AGOV plus a second factor), sent as `Authorization: Bearer` on the authorisation request |
| **Workflow Initiator**, portal-side login | `authorization_code` with `client_assertion`, or `urn:ietf:params:oauth:grant-type:jwt-bearer` with `assertion` | The ID token the portal obtained from a configured identity provider. It must be signed by that provider, issued to one of the portal's registered `idp_client_ids`, at most `EHEALTH_IUA_MAX_ID_TOKEN_AGE_SECONDS` old (600), linked to an account here, and at a level in the provider's `mfa_acr`. |

Without `person_id` the result is a **Basic Access Token**, which reaches
PIXm/PDQm. With `person_id` (the patient's EPR-SPID in CX form) it is an
**Extended Access Token** for that record, which reaches MHD and CH:ATC. The
token is a JWS (RS256 by default; ES256 with an EC key), `typ` `at+jwt`, five
minutes long, with the claims of the guide: `extensions.ihe_iua`
(`subject_name`, `home_community_id`, `subject_role`, `purpose_of_use`,
`person_id`), `extensions.ch_epr` (`user_id` = GLN or EPR-SPID with its
qualifier) and, for a technical user, `extensions.ch_delegation`.

### What the resource server checks, on every request

1. The signature, against the one configured key (the header's `alg` must be
   that key's algorithm, so `none`, HMAC and key-type confusion are refused);
   issuer; audience (this system's FHIR base); lifetime.
2. The token is in the registry and not revoked. A replayed authorisation
   code revokes the tokens issued from it.
3. The user in `ch_epr` still exists, and a professional's GLN is still
   backed by a live licence.
4. For an extended token, the **patient's consent, evaluated now**: role,
   purpose, exclusions and the confidentiality ceiling, the same decision the
   native API makes. A patient who excludes a doctor locks out that doctor's
   existing tokens at their next request. The token must also name the record
   the request touches.
5. The role limits what the token can do, whatever else it asks for:

| `subject_role` | `purpose_of_use` | MHD read | MHD write | ATC | PIXm/PDQm |
|---|---|---|---|---|---|
| PAT (own record only) | NORM | yes (up to *secret*) | yes | yes | no: the directory is for professionals |
| HCP | NORM, EMER | yes (consent ceiling) | yes | no | yes |
| TCU | AUTO | no | yes | no | yes |

Emergency access (EMER) is written to the audit trail as an emergency, with
the patient flagged for notification. Every issued, used and refused token is
in the audit trail; a refused request tells the caller only `invalid_token`.

### Registering a client

A portal, primary system or archive is registered in
`EHEALTH_IUA_CLIENTS` (a JSON list) at onboarding:

```json
[{
  "client_id": "kantonsspital-archiv",
  "name": "Kantonsspital Archiv",
  "client_secret_sha256": "<sha256 hex of the secret>",
  "public_key_pem": "<PEM public key that signs its token requests>",
  "public_key_id": "archiv-2026-09",
  "grant_types": ["client_credentials"],
  "technical_user_gln": "7601000000000"
}]
```

`ehealth.services.iua.new_client_secret()` returns a random secret and its
hash. Only the hash goes into the configuration. The client signs each token
request (RFC 9421) over `@method`, `@target-uri`, `authorization` and
`content-digest` with at most 60 seconds between `created` and `expires`;
this requires `client_secret_basic`, since the signature covers the
`Authorization` header. Production refuses to start without
`EHEALTH_IUA_SIGNING_KEY_PEM`, with a client that has no registered key,
with unsigned requests allowed, or with the placeholder
`EHEALTH_IUA_HOME_COMMUNITY_OID`.

Behind a reverse proxy, the server must see the external URL (uvicorn
`--proxy-headers` with `--forwarded-allow-ips`), because the signed
`@target-uri` is compared with the URL the request arrived on.

### Not supported, and refused rather than half-done

- The **Assistant** (ASS) and **Representative** (REP) roles, groups
  (`ch_group`) and SMART on FHIR **`launch`**.
- **Tokens from other communities' authorization servers.** Only tokens
  this system issued are accepted. Cross-community trust needs their keys
  and an agreement on how their users map to local accounts.
- **SAML** assertions (XUA), and the mTLS + XUA alternative the guide allows.
- Token Introspection, which the guide forbids for cross-community use.
- `traceparent` handling (appendix "Trace Context") is not implemented.

This system's own capability tokens (`X-Capability`, presented together with
the session token of the same person) remain accepted on MHD for this
system's portal. Presenting both kinds at once is refused.

## Not implemented yet

In roughly the order a community needs them:

| Profile | Purpose | Status |
|---|---|---|
| **IUA**, remaining parts | Assistant and representative roles, SMART `launch`, tokens from other communities, XUA/SAML | Not implemented; see above. ITI-71, 72 and 103 are implemented. |
| **MHD ITI-66**, metadata update (ITI-105/106) | Finding submission sets; changing document metadata | Not implemented. ITI-65, 67 and 68 are above. |
| **XDS.b / XCA** (ITI-18, 41, 43; ITI-38, 39) | The SOAP-based document exchange the EPD network still runs on between communities | Not implemented. This is the largest single piece of work. |
| **XCPD** (ITI-55) | Finding a patient in *other* communities | Not implemented |
| **PIX V3 / PDQ V3** (ITI-44, 45, 47) | The HL7v3 SOAP forms of the patient-identity transactions, still used between communities | Not implemented. Only the FHIR forms above exist. |
| **CH:ATC** patient audit trail | Patients (and their portals) reading who accessed the record | **Implemented** as `GET /v1/fhir/AuditEvent?patient.identifier=…[&date=…]`. Only the patient can read their own trail. Document events use CH:ATC codes; other events keep this system's own names under a local code system. Check the codes against the current value set. |
| **ATNA** (ITI-20) | Sending audit records to a central audit repository | Not implemented. The internal audit trail is complete and signed, but is not sent in ATNA form. |
| **CH:ADR / CH:PPQm** | Authorisation decisions and patient privacy policies | Not implemented. Consent is modelled internally. |
| **CH:EMED** | Exchanging medication documents | Not implemented. Medication is modelled internally. |
| **EPR-SPID allocation via the ZAS/CdC UPI service** | Obtaining the official EPR-SPID for a patient | Not implemented. The EPR-SPID is generated locally with the correct format and check digit, but a certified community must obtain it from the central compensation office. |

## Testing conformance

`tests/test_patient_directory.py`, `tests/test_documents_mhd.py`,
`tests/test_audit_fhir.py` and `tests/test_iua.py` check the shapes, status
codes and refusals above against this codebase. It cannot show that another implementation interprets
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
- IHE IUA: <https://profiles.ihe.net/ITI/IUA/>
- RFC 9421 HTTP Message Signatures; RFC 9530 Digest Fields; RFC 9068 JWT access tokens

The OIDs and profile versions used here should be checked against the
current edition of the CH EPR FHIR guide before the Projectathon. Guides are
revised each year, and a changed value fails a test case without breaking
anything here.
