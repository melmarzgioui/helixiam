# OpenID4VP verifier — OpenID Foundation conformance-suite run

HelixIAM's EUDI Wallet verifier (`docs/eudi-wallet.md`, **Experimental**) was run against the OpenID Foundation
conformance suite, with the suite playing the wallet. This is a self-run of the open-source suite, not an OpenID
Certification: certification is granted by the OpenID Foundation itself and was not requested.

**Outcome (2026-10-15):** every positive test HelixIAM was given ended in a real sign-in, and every negative test
was refused for the reason the test targets. The suite reported three kinds of finding. None is a HelixIAM defect,
so no product code changed: one is a suite heuristic, two follow from deliberate design choices (see
[Deviations](#deviations)). A HAIP requirement the suite does not test (the DCQL `trusted_authorities` query) is
listed under [Not covered by the suite](#not-covered-by-the-suite).

## What was run

| | |
|---|---|
| Suite | `registry.gitlab.com/openid/conformance-suite:latest`, reporting **version 5.3.3**, tag `release-v5.3.3`, revision **`f0133e9`** (`f0133e9ed72467c930bbc15e14d499785972e88d`, master 2026-10-14; the image was built 2026-10-15). Source: <https://gitlab.com/openid/conformance-suite> |
| HelixIAM | `master` at `298dd452` (no product changes were needed), jar on the host behind a TLS-terminating nginx |
| Plans | `oid4vp-1final-verifier-haip-test-plan` ("OpenID for Verifiable Presentations 1.0 Final/HAIP: Test a verifier", the certification plan; it fixes `vp_profile=haip`, `client_id_prefix=x509_hash`, `request_method=request_uri_signed`, and HAIP excludes `direct_post`) and `oid4vp-1final-verifier-test-plan` (the same modules without the HAIP profile, `vp_profile=plain_vp`; used for `x509_san_dns` and for `direct_post`) |
| Formats | `credential_format=sd_jwt_vc` (`dc+sd-jwt`, PID `urn:eudi:pid:1`) and `iso_mdl` (`mso_mdoc`, PID `eu.europa.ec.eudi.pid.1`) |
| Response modes | `direct_post.jwt` in the default (production) profile; `direct_post` in the `dev` profile, the only one that allows it |
| `client_id` prefixes | `x509_hash` and `x509_san_dns` |
| Flows | request by reference (`request_uri`, signed JAR) in every run; same-device (the wallet page's "Open wallet" link) for whole plans; cross-device (the QR code, decoded) for the happy flow of every combination; `request_uri_method=post` through providers configured for it |
| Logs | [`2026-10-15/`](2026-10-15/): the suite's JSON export of every plan (gzipped, secrets removed), the HelixIAM result page uploaded for every positive test (`screenshots/`), and [`results.json`](2026-10-15/results.json) (per module: status, result, findings, the page HelixIAM ended on) |

The harness that produced this run is in [`e2e/oid4vp-conformance/`](../../../e2e/oid4vp-conformance/) (see
[Reproducing the run](#reproducing-the-run)).

## Results

Columns count test modules. **Pass** = the suite's `PASSED` (negative tests: HelixIAM answered the bad response
with `400`). **Pass (review)** = every check passed and the suite waits for a person to look at the verification
evidence; that is the end state of every positive verifier test, and the evidence (a screenshot of HelixIAM's
signed-in account page) was uploaded. **Warning** = modules that passed or failed with at least one warning.

| Plan / variant | Flow | Pass | Pass (review) | Fail | Warning | Skipped | Suite plan id |
|---|---|---:|---:|---:|---:|---:|---|
| HAIP · `sd_jwt_vc` · `direct_post.jwt` · `x509_hash` | same-device | 7 | 3 | 1 (D2) | 1 (D1) | 0 | `IcPpM1y0hRb3S` |
| HAIP · `sd_jwt_vc` · `direct_post.jwt` · `x509_hash` | cross-device | 0 | 0 | 1 (D3) | 1 (D1) | 0 | `kowB4Wkirsgwd` |
| HAIP · `iso_mdl` · `direct_post.jwt` · `x509_hash` | same-device | 1 | 2 | 1 (D2) | 1 (D1) | 0 | `YFJBptdpy3Wfv` |
| HAIP · `iso_mdl` · `direct_post.jwt` · `x509_hash` | cross-device | 0 | 0 | 1 (D3) | 1 (D1) | 0 | `CD0MpRnyLQZ0e` |
| plain · `sd_jwt_vc` · `direct_post.jwt` · `x509_san_dns` | same-device | 7 | 3 | 1 (D2) | 1 (D1) | 0 | `41XSUZOPktSio` |
| plain · `sd_jwt_vc` · `direct_post.jwt` · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `ZVKvGVk2K6VF5` |
| plain · `iso_mdl` · `direct_post.jwt` · `x509_san_dns` | same-device | 1 | 2 | 1 (D2) | 1 (D1) | 0 | `6ztjpOT2lFhA4` |
| plain · `iso_mdl` · `direct_post.jwt` · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `fVMSl1ED9c5bn` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_hash` | same-device | 7 | 2 | 1 (D2) | 1 (D1) | 1 (S1) | `DBv6wduJkvZ8a` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_hash` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `NwgfzMl95fnvm` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_hash` | same-device | 1 | 1 | 1 (D2) | 1 (D1) | 1 (S1) | `RkAWseTi28Zre` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_hash` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `ql8r81RAdQs30` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_san_dns` | same-device | 7 | 2 | 1 (D2) | 1 (D1) | 1 (S1) | `iId93dFXpP3oO` |
| plain · `sd_jwt_vc` · `direct_post` (dev) · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `GlL3lZNFIuvKH` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_san_dns` | same-device | 1 | 1 | 1 (D2) | 1 (D1) | 1 (S1) | `xX21dX0qtIJsc` |
| plain · `iso_mdl` · `direct_post` (dev) · `x509_san_dns` | cross-device | 0 | 1 | 0 | 1 (D1) | 0 | `ZGIsgbINO7BYf` |
| **Total (68 modules)** | | **32** | **22** | **10** | **16** | **4** | |

Before those plans, each of the twelve providers was linked to the test account with one more happy flow run from
the account console's "Link wallet" (`final-setup-link-*` in `2026-10-15/`): 12 × pass (review), 11 with D1.

Per module (same-device plans; `sd_jwt_vc` has 11 modules, `iso_mdl` 4, since the SD-JWT-only tests do not apply to
mdoc):

| Module | `sd_jwt_vc` | `iso_mdl` | What HelixIAM did |
|---|---|---|---|
| `oid4vp-1final-verifier-happy-flow` | pass (review) | pass (review) | verified, signed the linked account in |
| `oid4vp-1final-verifier-minimal-cnf-jwk` | pass (review) | n/a | verified, signed in |
| `oid4vp-1final-verifier-request-uri-method-post` | pass (review) with `direct_post.jwt`; skipped (S1) in the `direct_post` runs | same | served the request object to the POST and echoed `wallet_nonce` |
| `oid4vp-1final-verifier-request-uri-fetched-twice` | **fail (D2)** | **fail (D2)** | second fetch of the `request_uri`: `404` |
| `oid4vp-1final-verifier-invalid-credential-signature` | pass | n/a | `400`, `wallet.issuer_signature_invalid` |
| `oid4vp-1final-verifier-invalid-kb-jwt-signature` | pass | n/a | `400`, `wallet.holder_binding_invalid` |
| `oid4vp-1final-verifier-invalid-sd-hash` | pass | n/a | `400`, `wallet.holder_binding_invalid` (sd_hash) |
| `oid4vp-1final-verifier-invalid-kb-jwt-nonce` | pass | n/a | `400`, `wallet.nonce_mismatch` |
| `oid4vp-1final-verifier-invalid-kb-jwt-aud` | pass | n/a | `400`, `wallet.audience_mismatch` |
| `oid4vp-1final-verifier-kb-jwt-iat-in-past` | pass | n/a | `400`, `wallet.holder_binding_invalid` (iat window) |
| `oid4vp-1final-verifier-kb-jwt-iat-in-future` | pass | n/a | `400`, `wallet.holder_binding_invalid` (iat window) |
| `oid4vp-1final-verifier-invalid-session-transcript` | n/a | pass | `400`, `wallet.holder_binding_invalid` (deviceSignature over the expected SessionTranscript) |

The refusal reasons are from HelixIAM's own log (`Wallet response refused: ... reason=`), checked for every negative
test: each was refused by the check the test aims at, not by something earlier.

## Deviations

Every finding the suite reported, with its root cause and what was done.

### D1 — `VP1FinalEnsureMinimumNonceEntropy` WARNING (27 of 28 happy flows) — justified, suite heuristic

*"Nonce does not appear to have sufficient entropy (calculated Shannon entropy is below the threshold)"*,
`OID4VP-1FINAL-5.2`, e.g. actual 92.1 bits against an expected 96.

**Root cause.** HelixIAM's nonce is 16 bytes from `SecureRandom`, base64url (22 characters): exactly the 128 bits
OpenID4VP PR #722 (which the warning cites) recommends, and the "at least 16 fresh bytes" of OpenID4VP §13.3. The suite
does not measure the nonce's entropy; it multiplies the string's per-character Shannon entropy by its length. A
22-character string reaches at most 22 × log2(22) ≈ 98.1 under that formula, and only when no character repeats. In a
simulation of 100 000 random 16-byte base64url nonces with the suite's formula the mean was 91.3 and **89 %** fell below
96; 24-byte and 32-byte nonces passed every time. The condition's own comment says the 96-bit threshold is meant to
avoid "false-positive failures on legitimate 128-bit nonces", which it does not do for base64url 128-bit nonces.

**Decision.** Not changed. The nonce meets the specification and the recommendation the suite cites; lengthening it
only to satisfy a character-frequency estimate would be changing behaviour for a heuristic. Worth reporting to the
suite (see [Concerns](#concerns)).

### D2 — `oid4vp-1final-verifier-request-uri-fetched-twice` FAILURE (all 8 same-device plans) — justified, deliberate single use

*"FetchRequestUriAndExtractRequestObject: Unable to fetch request_uri"* on the suite's second fetch; the test is then
`INTERRUPTED`.

**Root cause.** HelixIAM serves each request object once: `WalletTransactionStore#claimRequest` atomically moves the
transaction to `REQUEST_FETCHED` and records which of its two request ids (same-device or cross-device) was used;
another fetch of either is `404` (`OpenId4VpVerifierController`). This is security requirement 2 of the design
(`docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md` §10, "Single use of `requestId`, `responseId`, `nonce`
and `response_code`, enforced atomically") and `helix-iam-server/SECURITY-REVIEW.md` §B.2. OpenID4VP 1.0 neither
requires nor forbids a single-use `request_uri`; the test's own summary says so ("OID4VP 1.0 Final does not require
request_uri to be single-use, so a wallet may re-fetch").

**Decision.** Not changed: a test that needs behaviour HelixIAM deliberately does not have. What it costs: a wallet
that fetches the request object twice (a retry, a UI reload, a link preview) gets `404` and the login has to be
started again. The test is in the certification plan, so this would also fail a formal certification; whether to
allow re-fetching the *claimed* id until the response arrives is a maintainer decision (see [Concerns](#concerns)).

### D3 — HAIP cross-device: `VP1FinalEnsureDirectPostResponseHasRedirectUriForHaip` FAILURE — justified, HAIP scopes it to same-device

*"HAIP 1.0 §5.1 requires the verifier to include redirect_uri in the response to the wallet's POST to response_uri,
but it is missing"*, only in the two HAIP plans run cross-device.

**Root cause.** For a cross-device login HelixIAM answers the wallet's POST with `200 {}`: the browser that started
the login is on another device and learns the outcome by polling, so there is nothing for the phone to be redirected
to. HAIP 1.0 §5.1 puts the requirement inside "If 'same-device' flow is used, then: Verifiers MUST include
redirect_uri ..."; the same-device runs of the same plans return `redirect_uri` and pass the check. The suite cannot
tell the two flows apart, so it applies the same-device rule to both.

**Decision.** Not changed. Returning a `redirect_uri` to the phone in a cross-device login would send the phone's
browser to a callback it has no session for, and hand it the response code. HAIP also *recommends* using only the
same-device flow; HelixIAM offers both, as `docs/eudi-wallet.md` §8 already records.

### S1 — `oid4vp-1final-verifier-request-uri-method-post` SKIPPED in the `direct_post` runs — not a deviation

The test runs only when the authorization request carries `request_uri_method=post`. The dev-profile providers kept
the default (`get`, parameter absent); the `direct_post.jwt` runs used providers with `requestUriMethod=post` and pass.

### Variants not run

| Variant | Why |
|---|---|
| `request_method=url_query`, `client_id_prefix=redirect_uri` | Not supported, on purpose: HAIP requires signed requests by reference (JAR + `request_uri`), and `redirect_uri` requests cannot be signed (OpenID4VP §5.9.3). |
| W3C Digital Credentials API (`dc_api`, `dc_api.jwt`) | Not implemented yet (`docs/eudi-wallet.md` §8, `ROADMAP.md`). The suite's verifier plans have no DC API variant either. |
| mdoc `deviceMac` | Rejected by design (`docs/eudi-wallet.md` §8); no module of these plans presents it. |
| `client.rical` / `credential.vical` trust lists | Optional suite inputs; the request-object chain was checked against the single trust anchor instead (`client.request_object_trust_anchor_pem`). |

## Not covered by the suite

Found while reading the requirements next to the run, not reported by the suite:

- **HAIP §5: DCQL `trusted_authorities` of type `aki` "MUST be supported".** HelixIAM never sends `trusted_authorities`
  (`DcqlQueryBuilder`) and its matcher refuses a query that contains one (`DcqlResultMatcher`). Issuer trust is enforced
  after the fact (PKIX to the configured `trustAnchors`), so this is not a security gap, but a wallet holding several
  PIDs cannot be told which issuers are acceptable. The suite's verifier plans do not test it. Recorded as a follow-up
  in `ROADMAP.md`; not changed here.

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
  signed that user in; the screenshot of the resulting account page is the evidence uploaded to the suite.
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

- **D2 and certification.** `request-uri-fetched-twice` is part of the HAIP certification plan; with single-use
  request objects HelixIAM would fail it in a formal certification. Allowing the claimed request id to be fetched
  again until the response arrives would pass it without reopening the other id; it changes a "non-negotiable"
  design rule, so it needs a maintainer decision.
- **D1 upstream.** The nonce-entropy heuristic flags 128-bit base64url nonces about 89 % of the time; worth an issue on
  the suite's tracker (third party).
- **Interop is still unproven against real wallets.** The suite is one implementation of the wallet side; the EU
  reference wallet and national test wallets (Phase 4 in `ROADMAP.md`) remain to be tried.
- **Formal certification** needs the OpenID Foundation (membership/fee, their review of the logs); out of scope here.
