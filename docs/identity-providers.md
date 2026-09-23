# Identity providers: SwissID, HIN and others

Login is delegated to a federated identity provider via OpenID Connect. This
system stores no passwords. It verifies what the provider asserts, checks that
the asserted **level of assurance** is good enough, and only then opens a
session. This document covers configuring a provider, testing against its real
integration environment, and the parts that are still yours to do.

## The model

```
browser ──► POST /v1/auth/login?provider=hin ──► provider's login page
                                                     │ (user authenticates)
browser ◄── redirect with code ◄─────────────────────┘
browser ──► POST /v1/auth/callback {state, code}
              │ token exchange (PKCE + client authentication)
              │ ID token: signature, issuer, audience, expiry, nonce
              │ acr checked against the provider's policy
              ├─ acr in mfa_acr  ──► session active   (second_factor: "idp")
              └─ otherwise       ──► email code sent  (second_factor: "otp-email")
                                     └─ POST /v1/auth/mfa/verify ──► session active
```

`GET /v1/auth/providers` lists the configured provider names for a login page.
Each login flow records which provider it started with, and only that
provider can finish it.

## Level of assurance

Every provider reports in the ID token's `acr` claim how strongly it
authenticated the user. Each provider has three settings:

| Setting | Effect |
|---|---|
| `accepted_acr` | Below this the login is refused. **Required in production**: without it, a login that only proved control of a mailbox would be accepted. |
| `mfa_acr` | The provider has already checked two factors, so the login completes without the emailed code. Must be a subset of `accepted_acr`. |
| `professional_acr` | A stricter floor for people who hold the healthcare-professional role. Leave empty to apply `accepted_acr` to everyone. |

`acr_values` is what we *ask* for. It is only a request: the provider may
answer with a lower level, which is why the answer is checked again.

**Use each provider's own names for its levels.** SwissID and HIN do not share
a vocabulary, and the values in this repository's tests (`loa-2`, `hin-2fa`)
are placeholders. Take the real values from each provider's relying-party
documentation and confirm them against its integration environment (below).
Getting them wrong fails safe: every login is refused.

### Why a strong provider level can replace the email code

In the Swiss EPR (EPD) model, users authenticate with an **identification
means certified under the EPD ordinances**, and that certified means provides
the two factors. When the provider asserts such a level, adding our own
emailed code gives little extra security, because email is weaker than the
provider's second factor. So the email code stays as the second factor only
for levels below `mfa_acr`.

Which providers are currently certified as EPD identification means, and
which of their levels count, is published by eHealth Suisse. Check the
current list rather than relying on this document.

## Client authentication

| Method | Setting | Use |
|---|---|---|
| `client_secret_post` | `client_secret` | Default. The provider and this system share a secret. |
| `private_key_jwt` (RFC 7523) | `private_key_pem`, `private_key_id` | **Preferred.** For each token request we sign a short-lived assertion (60 s, single-use `jti`, audience = the token endpoint). The private key never leaves this system. |

For `private_key_jwt`:

```bash
# EC P-256 (or RSA ≥ 2048 bit)
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt > client-key.pem
```

Put the PEM in the secret store behind `EHEALTH_SWISSID_PRIVATE_KEY_PEM`, never
in the repository, and give it a dated key id such as `dossier-2026-09`. The
public half is served at `GET /v1/auth/jwks.json`. Register that URL, or the
key it returns, with the provider.

To rotate: publish the new key alongside the old one, switch the key id, and
remove the old key once no assertion signed with it can still be in flight
(60 seconds is enough).

## Several providers

SwissID is configured with the flat `EHEALTH_SWISSID_*` variables. Further
providers go in `EHEALTH_EXTRA_IDENTITY_PROVIDERS` as a JSON list:

```json
[{
  "name": "hin",
  "issuer": "https://<HIN OIDC issuer>",
  "client_id": "…",
  "client_auth_method": "private_key_jwt",
  "private_key_pem": "…",
  "private_key_id": "dossier-2026-09",
  "redirect_uri": "https://dossier.example.ch/auth/callback",
  "accepted_acr": ["<HIN level>"],
  "mfa_acr": ["<HIN level>"]
}]
```

A person can hold **one login identity per provider**. For example, a
physician can log in through HIN at the practice and through SwissID as a
patient: both identities belong to the same person, and the audit trail
records which one was used. Two identities for the same person at the *same*
provider are refused. Accounts are keyed by issuer *and* subject, so the same
subject string arriving from another provider is a different identity.

Linking an identity to a person is an explicit enrolment step
(`POST /v1/auth/accounts/link`, admin key). A valid identity this system has
never seen gets nothing.

## Testing against the real provider

The test suite covers the OIDC client against an in-process provider that
signs real tokens, rotates keys, enforces PKCE and verifies our
`private_key_jwt` assertion (`tests/test_oidc_provider.py`). That shows the
cryptography and the protocol are right. It **does not** show that SwissID's
or HIN's actual responses match, and nothing in this repository can, because
their integration environments need credentials this project doesn't hold.

Before going live, run through this list against each provider's integration
environment:

1. Register a test client and obtain its credentials. With `private_key_jwt`,
   register the JWKS URL.
2. Set `EHEALTH_USE_MOCK_IDP=false` and the provider's settings in a staging
   deployment.
3. Log in once at each level the provider offers. Record the `acr` values it
   actually returns (they appear in the audit trail as `idp_acr`) and set
   `accepted_acr`, `mfa_acr` and `professional_acr` from those values, not
   from the documentation alone.
4. Confirm that a level below `accepted_acr` is refused with 401 and appears
   in the audit trail as `login.failed` with the reason.
5. Replay a used callback: it must fail.
6. Wait for or trigger a signing-key rotation at the provider, then log in:
   the client must pick up the new key without a restart.
7. Log in as a user holding the professional role at a level below
   `professional_acr`: it must be refused.
8. Record the results with the date and the provider's environment name.
   The certification body will ask for this evidence
   (see [`certification.md`](certification.md)).

## Not implemented yet

- **SAML.** Some professional and community identity providers speak only
  SAML 2.0, which is also what IHE XUA uses to carry identity between EPD
  communities. Only OpenID Connect is implemented here.
- **Passkeys or TOTP as our own second factor.** Below `mfa_acr` the only
  factor we issue ourselves is the emailed code. The better fix is usually to
  require a provider level that already includes two factors.
- **The federal e-ID.** Once the e-ID infrastructure offers an OpenID Connect
  interface, it becomes one more entry in `EXTRA_IDENTITY_PROVIDERS`.
- **Logout at the provider.** Our own sessions end properly, but the
  provider's session is not ended (RP-initiated logout is not implemented).
