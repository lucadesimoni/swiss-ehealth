# The API, for partners

Everything is HTTP + JSON under `/v1`, described by an OpenAPI document the
service generates itself (`/openapi.json` outside production). There is no
second, private interface — the UI a patient uses and the integration a
hospital information system uses are the same API, which is the only way an
API stays honest.

## Two credentials, two questions

```
Authorization: Bearer <session token>    who is calling
X-Capability:  <capability token>        what they may do, to which dossier
X-Holder-Key:  <public key>              optional proof-of-possession
X-Request-Id:  <your correlation id>     echoed back on every response
```

Separating them is deliberate. A session says a person authenticated at AAL2
and holds certain roles; a capability says *this dossier, this purpose, this
confidentiality ceiling, these scopes, for the next ten minutes*. A partner
integration that only ever reads medication for one patient never holds
anything broader than that.

## Errors: RFC 9457, always

Every failure — validation, authorisation, not-found, internal — returns
`application/problem+json`:

```json
{
  "type": "https://docs.dossier.example.ch/problems/access-denied",
  "title": "Access denied",
  "status": 403,
  "instance": "/v1/dossiers/dos_01KZE.../documents"
}
```

Branch on `type`, never on `title` or `detail`: those are for humans and may be
reworded. Authorisation failures deliberately carry no reason — the ledger has
it, and a caller who could distinguish "no such dossier" from "not allowed"
could map the record's structure by probing.

## Versioning the contract

| | Meaning | Where |
|---|---|---|
| `/v1` | the HTTP contract | the URL |
| `schema_version` | the database shape | `GET /v1/version` |
| `audit_payload_version` | the signed ledger layout | `GET /v1/version` |
| `bundle_format_version` | the offline bundle layout | `GET /v1/offline/public-key` |

Additive changes — new endpoints, new optional fields, new enum members on
*output* — happen within `v1`. Anything that could break a client hard-coding
today's behaviour gets `/v2`, with `v1` kept running. The rules are in
[`versioning.md`](versioning.md); what matters to a partner is that a URL keeps
meaning what it meant.

Request bodies reject unknown fields (`422`) rather than ignoring them. A
silently dropped field in a health API is a silently dropped clinical
instruction.

## Integrating

### 1. Enrol (back office, admin key)

`POST /v1/organizations`, `/v1/persons`, `/v1/persons/{uid}/credentials`,
`/v1/dossiers`. These carry `X-Admin-Key` and are meant for a registration
system, not for end users. With no key configured they return `404` — the
endpoints are off by default rather than open by default.

### 2. Authenticate a person

`POST /v1/auth/login` → SwissID → `POST /v1/auth/callback` → emailed code →
`POST /v1/auth/mfa/verify` → session + refresh token. Refresh tokens are
single-use; replaying one destroys the session, so store exactly one.

### 3. Get a capability

The patient grants (`POST /v1/grants`), the professional exchanges the grant
for a token (`POST /v1/grants/{uid}/token`). Supplying `holder_key` binds the
token to a key you hold, which turns token theft into "needs the private key
too".

### 4. Read and write

`/v1/dossiers/{uid}/documents`, `/v1/dossiers/{uid}/medications`,
`/v1/dossiers/{uid}/medications/reconciled`. Consent is re-evaluated on every
call, so a `403` on a request that worked a minute ago is not a bug — the
patient changed their mind, and that is the system working.

## Offline, for partner apps too

The offline bundle is not a patient-only feature. Any partner shipping an app
that must work without connectivity uses the same mechanism:

```
GET  /v1/offline/public-key      unauthenticated, cache it
POST /v1/offline/bundle          the patient's record, signed
POST /v1/offline/emergency-dataset   < 2 KB, QR-sized
POST /v1/offline/sync            idempotent upload of offline captures
```

Verification needs the public key and nothing else. The algorithm is Ed25519
over the canonical JSON body; `verify_bundle()` in
`src/ehealth/services/offline.py` is deliberately a free function with no
database and no framework so it can be reimplemented in Swift, Kotlin or
TypeScript by reading it.

Three properties a client must implement correctly:

- **Check `expires_at` and show staleness.** An expired bundle still verifies —
  it is still authentic — and presenting a two-year-old medication list as
  current is a clinical hazard.
- **Generate `client_uid` once per captured entry and keep it across retries.**
  It is the idempotency key; a fresh id on retry creates a duplicate entry.
- **Do not trust your own clock.** Send `captured_at`, but expect the server's
  ordering to win.

## Rate limits and idempotency

Rate limiting belongs at your ingress; this service does not implement it. Sync
is idempotent by `client_uid`; other `POST`s are not, so retry them only on a
network error, never on a `4xx`.

## What is not there yet

- **Machine-to-machine credentials.** A partner *system* has no identity of its
  own: every call is made on behalf of an authenticated person or with the
  admin key. Client-credentials with per-partner scopes is the next thing this
  API needs, and pretending otherwise would mislead an integration plan.
- **Webhooks / change feed.** Partners poll. The audit ledger is the natural
  source for a cursor-based feed, but it is not exposed as one.
- **IHE profiles** (XDS.b, PIX/PDQ, CH:ATC) needed to federate with other EPDG
  communities. The internal model is shaped to map onto them.
- **Bulk export** beyond a single patient's bundle.
