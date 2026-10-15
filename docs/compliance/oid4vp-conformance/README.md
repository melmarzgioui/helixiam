# OpenID4VP verifier — OpenID Foundation conformance-suite run

HelixIAM's EUDI Wallet verifier (`docs/eudi-wallet.md`, **Experimental**) was run against the OpenID Foundation
conformance suite, with the suite playing the wallet. This is a self-run of the open-source suite, not an OpenID
Certification: certification is granted by the OpenID Foundation itself and was not requested.

**Outcome (2026-10-15).** Two runs on the same day:

1. **First run** (`master` `298dd452`): every positive test signed the linked account in, every negative test was
   refused by the check it targets, and the suite reported three findings (D1–D3 below).
2. **Re-run after the fixes** (branch `test/oid4vp-conformance`, commits `e1133255`, `af3626e7`, `a6d4463c`): D2 is
   fixed, so `request-uri-fetched-twice` now passes in every plan. HAIP's DCQL `trusted_authorities` (`aki`), which
   the suite does not test, is now sent. D1 (a suite heuristic, issue drafted for the suite) and D3 (a same-device rule
   the suite also applies to cross-device logins) remain, each justified below.

| Finding | Result | Status |
|---|---|---|
| D1 — nonce-entropy WARNING | warning on the happy flows | **justified**: suite heuristic; [issue drafted](upstream-issue-nonce-entropy.md) |
| D2 — `request-uri-fetched-twice` FAILURE | 8 failures in the first run, 0 in the re-run | **fixed** (`e1133255`) |
| D3 — HAIP cross-device `redirect_uri` FAILURE | 2 failures in both runs | **justified**: HAIP §5.1 requires it only for same-device |
| HAIP §5 `trusted_authorities` (not tested by the suite) | not sent in the first run | **implemented** (`a6d4463c`) |

## What was run

| | |
|---|---|
| Suite | `registry.gitlab.com/openid/conformance-suite:latest`, reporting **version 5.3.3**, tag `release-v5.3.3`, revision **`f0133e9`** (`f0133e9ed72467c930bbc15e14d499785972e88d`, master 2026-10-14; the image was built 2026-10-15). Source: <https://gitlab.com/openid/conformance-suite> |
| HelixIAM | first run: `master` `298dd452`; re-run: `a6d4463c` (D2 fix and `trusted_authorities`). The jar ran on the host behind a TLS-terminating nginx |
| Plans | `oid4vp-1final-verifier-haip-test-plan` ("OpenID for Verifiable Presentations 1.0 Final/HAIP: Test a verifier", the certification plan; it fixes `vp_profile=haip`, `client_id_prefix=x509_hash`, `request_method=request_uri_signed`, and HAIP excludes `direct_post`) and `oid4vp-1final-verifier-test-plan` (the same modules without the HAIP profile, `vp_profile=plain_vp`; used for `x509_san_dns` and for `direct_post`) |
| Formats | `credential_format=sd_jwt_vc` (`dc+sd-jwt`, PID `urn:eudi:pid:1`) and `iso_mdl` (`mso_mdoc`, PID `eu.europa.ec.eudi.pid.1`) |
| Response modes | `direct_post.jwt` in the default (production) profile; `direct_post` in the `dev` profile, the only one that allows it |
| `client_id` prefixes | `x509_hash` and `x509_san_dns` |
| Flows | request by reference (`request_uri`, signed JAR) in every run; same-device (the wallet page's "Open wallet" link) for whole plans; cross-device (the QR code, decoded) for the happy flow of every combination; `request_uri_method=post` through providers configured for it |
| Logs | re-run: [`2026-10-15-rerun/`](2026-10-15-rerun/); first run: [`2026-10-15/`](2026-10-15/). Each holds the suite's JSON export of every plan (gzipped, secrets removed), the HelixIAM result page uploaded for every positive test (`screenshots/`), and `results.json` (per module: status, result, findings, the page HelixIAM ended on) |

The harness that produced both runs is in [`e2e/oid4vp-conformance/`](../../../e2e/oid4vp-conformance/) (see
[Reproducing the run](#reproducing-the-run)).

## Results

Columns count test modules. **Pass** = the suite's `PASSED` (negative tests: HelixIAM answered the bad response
with `400`). **Pass (review)** = every check passed and the suite waits for a person to look at the verification
evidence; that is the end state of every positive verifier test, and the evidence (a screenshot of HelixIAM's
signed-in account page) was uploaded. **Warning** = modules that passed or failed with at least one warning.

### Re-run after the fixes (`a6d4463c`)

| Plan / variant | Flow | Pass | Pass (review) | Fail | Warning | Skipped | Suite plan id |
|---|---|---:|---:|---:|---:|---:|---|
| HAIP · `sd_jwt_vc` · `direct_post.jwt` · `x509_hash` | same-device | 7 | 4 | 0 | 1 (D1) | 0 | `WC8reGu9cIEV4` |
| HAIP · `sd_jwt_vc` · `direct_post.jwt` · `x509_hash` | cross-device | 0 | 0 | 1 (D3) | 1 (D1) | 0 | `q2l6BsuEBRKVD` |
| HAIP · `iso_mdl` · `direct_post.jwt` · `x509_hash` | same-device | 1 | 3 | 0 | 1 (D1) | 0 | `Yv3qZBWB7MZzw` |
| HAIP · `iso_mdl` · `direct_post.jwt` · `x509_hash` | cross-device | 0 | 0 | 1 (D3) | 1 (D1) | 0 | `LwjiTlRSfdY0q` |
| plain · `sd_jwt_vc` · `direct_post.jwt` · `x509_san_dns` | same-device | 7 | 4 | 0 | 1 (D1) | 0 | `z2b4Yqt4xztNk` |
| plain · `sd_jwt_vc` · `direct_post.jwt` · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `RULY9bKZeh7lD` |
| plain · `iso_mdl` · `direct_post.jwt` · `x509_san_dns` | same-device | 1 | 3 | 0 | 1 (D1) | 0 | `Le08FpaFpjzK1` |
| plain · `iso_mdl` · `direct_post.jwt` · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `bkEUJYKIbxQgB` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_hash` | same-device | 7 | 3 | 0 | 1 (D1) | 1 (S1) | `WkOQp1v5be0wf` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_hash` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `pfxHElEnbSqLz` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_hash` | same-device | 1 | 2 | 0 | 1 (D1) | 1 (S1) | `1rHaTweNGTVmr` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_hash` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `EQwGz6tlkuNvL` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_san_dns` | same-device | 7 | 3 | 0 | 1 (D1) | 1 (S1) | `MayvNmlWbiBey` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `tjsvQXlB2ofVi` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_san_dns` | same-device | 1 | 2 | 0 | 1 (D1) | 1 (S1) | `IbBHS7Dq6WGJ0` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `AR7lQgB91G4rt` |
| **Total (68 modules)** | | **32** | **30** | **2** | **16** | **4** | |

Before those plans, each of the twelve providers was linked to the test account with one more happy flow run from
the account console's "Link wallet" (`rerun-setup-link-*`): 12 × pass (review), each with D1.

In both of the suite's DCQL checks (`ValidateDCQLQuery`, which validates against the suite's DCQL JSON schema, and
`CheckForUnexpectedParametersInDcqlQuery`) the queries now carrying `trusted_authorities` passed. The suite's wallet
does not choose credentials by it, so the run shows only that the shape is accepted. Its effect is covered by
HelixIAM's own tests.

### First run (`298dd452`)

| Plan / variant (same combinations as above) | Pass | Pass (review) | Fail | Warning | Skipped |
|---|---:|---:|---:|---:|---:|
| 8 same-device plans | 32 | 16 | 8 (D2) | 8 (D1) | 4 (S1) |
| 8 cross-device happy flows | 0 | 6 | 2 (D3) | 8 (D1) | 0 |
| **Total (68 modules)** | **32** | **22** | **10** | **16** | **4** |

Per-plan counts and suite plan ids are in [`2026-10-15/results.json`](2026-10-15/results.json).

### Per module

Same-device plans. `sd_jwt_vc` has 11 modules and `iso_mdl` has 4, because the SD-JWT-only tests do not apply to
mdoc.

| Module | `sd_jwt_vc` | `iso_mdl` | What HelixIAM did |
|---|---|---|---|
| `oid4vp-1final-verifier-happy-flow` | pass (review) | pass (review) | verified, signed the linked account in |
| `oid4vp-1final-verifier-minimal-cnf-jwk` | pass (review) | n/a | verified, signed in |
| `oid4vp-1final-verifier-request-uri-method-post` | pass (review) with `direct_post.jwt`; skipped (S1) in the `direct_post` runs | same | served the request object to the POST and echoed `wallet_nonce` |
| `oid4vp-1final-verifier-request-uri-fetched-twice` | pass (review); first run: fail (D2) | pass (review); first run: fail (D2) | served the same request object to the second fetch, then verified and signed in |
| `oid4vp-1final-verifier-invalid-credential-signature` | pass | n/a | `400`, `wallet.issuer_signature_invalid` |
| `oid4vp-1final-verifier-invalid-kb-jwt-signature` | pass | n/a | `400`, `wallet.holder_binding_invalid` |
| `oid4vp-1final-verifier-invalid-sd-hash` | pass | n/a | `400`, `wallet.holder_binding_invalid` (sd_hash) |
| `oid4vp-1final-verifier-invalid-kb-jwt-nonce` | pass | n/a | `400`, `wallet.nonce_mismatch` |
| `oid4vp-1final-verifier-invalid-kb-jwt-aud` | pass | n/a | `400`, `wallet.audience_mismatch` |
| `oid4vp-1final-verifier-kb-jwt-iat-in-past` | pass | n/a | `400`, `wallet.holder_binding_invalid` (iat window) |
| `oid4vp-1final-verifier-kb-jwt-iat-in-future` | pass | n/a | `400`, `wallet.holder_binding_invalid` (iat window) |
| `oid4vp-1final-verifier-invalid-session-transcript` | n/a | pass | `400`, `wallet.holder_binding_invalid` (deviceSignature over the expected SessionTranscript) |

The refusal reasons come from HelixIAM's own log (`Wallet response refused: ... reason=`). For every negative test we
checked that the response was refused by the check the test aims at, not by an earlier one.

## Deviations

Every finding the suite reported, with its root cause and what was done.

### D1 — `VP1FinalEnsureMinimumNonceEntropy` WARNING (happy flows) — justified, suite heuristic

*"Nonce does not appear to have sufficient entropy (calculated Shannon entropy is below the threshold)"*,
`OID4VP-1FINAL-5.2`; for example, an actual 92.1 bits against an expected 96.

**Root cause.** HelixIAM's nonce is 16 bytes from `SecureRandom`, base64url (22 characters). That is exactly the
128 bits OpenID4VP PR #722 recommends (the PR the warning cites), and the "at least 16 fresh bytes" of OpenID4VP
§13.3. The suite does not measure the nonce's entropy. It multiplies the string's per-character Shannon entropy by its
length, so a 22-character string scores at most 22 × log2(22) ≈ 98.1, and only when no character repeats. In a
simulation of 100,000 random 16-byte base64url nonces, the mean score was 91.3 and **89 %** fell below 96. 24-byte and
32-byte nonces passed every time.

**Decision.** Not changed. The nonce meets the specification and the recommendation the suite cites. Lengthening it
only to satisfy a character-frequency estimate would change behaviour to please a heuristic. A factual issue for
the suite's tracker, with the measurement, the simulation and suggested fixes, is in
[`upstream-issue-nonce-entropy.md`](upstream-issue-nonce-entropy.md) (to be filed by the maintainer).

### D2 — `oid4vp-1final-verifier-request-uri-fetched-twice` FAILURE — **fixed**

*"FetchRequestUriAndExtractRequestObject: Unable to fetch request_uri"* on the suite's second fetch, in all 8
same-device plans of the first run.

**Root cause.** HelixIAM served each request object once: `claimRequest` moved the transaction to `REQUEST_FETCHED`,
and any later fetch got `404`. Real wallets retry a `request_uri` fetch after a network error, and the HAIP
certification plan tests for this.

**Fix (`e1133255`, maintainer ruling).**
- The first fetch binds the transaction to its flow, and the other flow's request id stays refused.
- The **same** request id may be fetched again while the transaction is `REQUEST_FETCHED`.
- Once the response has been received, or the transaction has ended or expired, the request id gets `404`.
- The response stays strictly single use.
- This is one atomic step in all three stores: the in-memory compute, the Redis Lua script, and one PostgreSQL
  `UPDATE … RETURNING`.
- The request object's `iat` is now the transaction's creation, so a re-fetch carries the same claims, unless an admin
  edits the provider between fetches (`response_mode` and `client_metadata` are read from the live config). A POST
  fetch's `wallet_nonce` and the ECDSA signature always differ, which is why the object is re-signed rather than
  stored.
- A request id fetched under another realm or alias is a `404` that leaves the transaction alone (before, it failed
  the transaction, which with re-fetching would let a QR observer cancel the real login). The residual risk of
  re-fetching is recorded in `SECURITY-REVIEW.md` §B.2.

Tests: the store contract suite runs the same cases against memory, Redis and PostgreSQL: a same-flow re-fetch, a
cross-flow fetch, a fetch after the response, after the end of the transaction and after expiry, the single-use
response, and the same/cross race. Over HTTP, `WalletFlowE2eTest` covers the same rules. The ruling and why a
re-fetch exposes nothing new are recorded in the wallet spec (security requirement 2) and
`helix-iam-server/SECURITY-REVIEW.md` §B.2. Re-run: the module passes in all 8 same-device plans.

### D3 — HAIP cross-device: `VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip` FAILURE — justified, HAIP scopes it to same-device

*"HAIP 1.0 §5.1 requires the verifier to include redirect_uri in the response to the wallet's POST to response_uri,
but it is missing"*. This appears only in the two HAIP plans run cross-device.

**Root cause.** For a cross-device login, HelixIAM answers the wallet's POST with `200 {}`. The browser that started
the login is on another device and learns the outcome by polling, so the phone has nowhere to be redirected to.
HAIP 1.0 §5.1 places the requirement under "If 'same-device' flow is used, then: Verifiers MUST include
redirect_uri ...". The same-device runs of the same plans return `redirect_uri` and pass the check. The suite cannot
tell the two flows apart, so it applies the same-device rule to both.

**Decision.** Not changed. Returning a `redirect_uri` to the phone in a cross-device login would send the phone's
browser to a callback it has no session for, and hand it the response code. HAIP also *recommends* using only the
same-device flow. HelixIAM offers both, as `docs/eudi-wallet.md` §8 already records.

### S1 — `oid4vp-1final-verifier-request-uri-method-post` SKIPPED in the `direct_post` runs — not a deviation

The test runs only when the authorization request carries `request_uri_method=post`. The dev-profile providers kept
the default (`get`, parameter absent). The `direct_post.jwt` runs used providers with `requestUriMethod=post`, and
those pass.

### HAIP §5 `trusted_authorities` — not tested by the suite — **implemented**

HAIP 1.0 §5 says the `aki` Trusted Authority Query for DCQL (OpenID4VP 1.0 §6.1.1.1) "MUST be supported". Before
`a6d4463c`, HelixIAM never sent it.

Every PID Credential Query now carries:

```json
"trusted_authorities": [ { "type": "aki", "values": ["YI4DKFMNjUMJ257VU58eJstIS64", "eGT0tVUfwa31mB_GDKFKX3bVc6E"] } ]
```

(These are the values from the re-run.)
- **Values.** The unpadded base64url key identifiers of the provider's trust anchors and pinned intermediates: the
  SubjectKeyIdentifier, else RFC 5280 method 1. This is the AuthorityKeyIdentifier of every certificate those CAs
  issue. In the run, they equal the SKIs of the test issuer root and of the suite's IACA root.
- **Default.** Per provider via `dcql.trustedAuthorities`. Unset means on under the HAIP profile (`x509_hash` with
  `direct_post.jwt`) and off otherwise. The console has a Default/On/Off choice in the Credentials section.
- **Enforcement.** PKIX validation to the trust anchors still decides. The matcher accepts one well-formed `aki`
  query and does not act on it.
- **Never guessed.** If any anchor or pinned intermediate has no SubjectKeyIdentifier, the query leaves
  `trusted_authorities` out (one WARN per loaded provider), and saving the setting explicitly On is refused with a
  `400` on `dcql.trustedAuthorities`. If a wallet returns no credential, Off is the escape hatch.

### Variants not run

| Variant | Why |
|---|---|
| `request_method=url_query`, `client_id_prefix=redirect_uri` | Not supported, on purpose: HAIP requires signed requests by reference (JAR + `request_uri`), and `redirect_uri` requests cannot be signed (OpenID4VP §5.9.3). |
| W3C Digital Credentials API (`dc_api`, `dc_api.jwt`) | Not implemented yet (`docs/eudi-wallet.md` §8, `ROADMAP.md`). The suite's verifier plans have no DC API variant either. |
| mdoc `deviceMac` | Rejected by design (`docs/eudi-wallet.md` §8); no module of these plans presents it. |
| `client.rical` / `credential.vical` trust lists | Optional suite inputs; the request-object chain was checked against the single trust anchor instead (`client.request_object_trust_anchor_pem`). |

## Test setup

- **Network.** The suite (`oidf-suite-server`, `oidf-suite-nginx`, `oidf-mongodb`) and an nginx TLS proxy
  (`oidf-helix-proxy`) share the Docker network `oidf-net`. HelixIAM runs on the host
  (`IDP_BASE_URL=https://helix-oidf.localtest.me:18943`); the proxy has the network alias `helix-oidf.localtest.me`
  and listens on 18943 inside and outside Docker, so the suite and the browser use the same URLs (`*.localtest.me`
  resolves to 127.0.0.1 in public DNS). The proxy's certificate comes from a throwaway local CA.
- **Proxy settings.** `HELIX_TRUSTED_PROXIES=127.0.0.1/32,::1/128` (Docker Desktop connects to the host from the
  loopback address), so `X-Forwarded-Proto/Host/Port` are honoured and every URL HelixIAM hands out is
  `https://helix-oidf.localtest.me:18943/...`; `HELIX_ALLOWED_HOSTS=helix-oidf.localtest.me:18943`. In the production
  profile the stored `direct_post` providers were refused at load ("responseMode direct_post (unencrypted) is allowed
  only in the dev profile"), as intended.
- **Verifier access certificate.** EC P-256 leaf with `SAN DNS:helix-oidf.localtest.me` (for `x509_san_dns`), issued
  by an intermediate under a test root. HelixIAM imports leaf + intermediate (`POST /admin/realms/oidf/verifier-keys`),
  so `x5c` never carries the root (HAIP §5); the root is the suite's `client.request_object_trust_anchor_pem`, and
  for `x509_san_dns` the suite's `client.client_id` is the host name.
- **Issuer trust.** The suite signs SD-JWT VCs with the `credential.signing_jwk` of the test configuration: a document
  signer under a test issuer root, `x5c` = the signer only. It signs mdocs with a document signer it mints under its
  own published IACA root (`/mdoc-iaca-root.pem`). Both roots are the providers' `trustAnchors`.
  `revocationChecking=OFF`: neither test issuer has a reachable CRL or OCSP endpoint (the IACA names
  `http://example.com/myca.crl`), and issuer revocation is not what these plans test.
- **Subject.** The suite's PIDs (Jean Dupont, FR) carry no `personal_administrative_number`, so HelixIAM cannot create
  an account from them (`docs/eudi-wallet.md` §6). The providers set `subject.acknowledgeWeakSubject=true`, a test
  user `jean.dupont` linked each provider once through the account console, and every later positive test then
  signed that user in; the screenshot of the resulting account page is the evidence uploaded to the suite (a JPEG of the viewport: the suite refuses uploads over 500 KB).
- **Driving.** A Playwright script opens the HelixIAM wallet page (`/realms/oidf/broker/<alias>`), gives the suite the
  "Open wallet" link (same-device) or the decoded QR code (cross-device) through the test's authorization endpoint,
  visits the `redirect_uri` the suite received from the same browser (same-device; cross-device: the page's own
  status polling moves on), and uploads the screenshot.
- **Admin API.** Seeded with `helix.admin.dev-open=true` from the host, a test-harness convenience only.

## Reproducing the run

Needs Docker, a JDK 21 + Maven build of `helix-iam-server`, Node.js, `jq`, `openssl`. From the repository root:

```bash
(cd helix-iam-server && mvn -B -DskipTests package)
cd e2e/oid4vp-conformance
export OIDF_WORK=/tmp/helixiam-oidf-work            # keys, logs and exports; never inside the repository
(cd driver && npm install && npx playwright install chromium-headless-shell)
./stack.sh up && ./pki.sh && ./stack.sh proxy
./run-helix.sh prod &                               # wait for http://localhost:18080/actuator/health/readiness
./seed.sh
(cd driver && for s in $(node gen-specs.mjs prod final); do node run-plan.mjs "$s"; done)
kill %1; ./run-helix.sh dev &
./seed.sh direct_post
(cd driver && for s in $(node gen-specs.mjs dev final); do node run-plan.mjs "$s"; done)
./export.sh final "$(date +%F)"                     # redacted logs into docs/compliance/oid4vp-conformance/<date>/
kill %2; ./stack.sh down
```

Ports (`env.sh`): suite 18443, HelixIAM 18080, TLS proxy 18943, PostgreSQL 15432; every container is named `oidf-*`.
The suite UI is at `https://localhost:18443` while the stack is up.

**Redaction.** `export.sh` removes the private members of every JWK (the issuer key is in the test configuration the
suite stores with each test), any PEM private key and every `response_code`; the screenshots become JPEG files. The
suite's `.sig` files are dropped because they no longer verify after redaction. Request ids and nonces in the logs are
spent single-use values of finished transactions.

## Concerns

- **D3 and certification.** The HAIP cross-device happy flow fails a check that HAIP scopes to same-device logins. A
  formal certification run would use same-device, which passes. If the Foundation's reviewers expect cross-device to
  pass too, this needs a conversation with them, not a code change.
- **D1 upstream.** The nonce-entropy heuristic flags about 89 % of 128-bit base64url nonces. The issue text is ready
  ([`upstream-issue-nonce-entropy.md`](upstream-issue-nonce-entropy.md)); filing it is up to the maintainer (third
  party).
- **Interop is still unproven against real wallets.** The suite is one implementation of the wallet side. The EU
  reference wallet and national test wallets (Phase 4 in `ROADMAP.md`) remain to be tried, including whether they act
  on `trusted_authorities`.
- **Formal certification** needs the OpenID Foundation (membership or fee, and its review of the logs). It is out of
  scope here.
