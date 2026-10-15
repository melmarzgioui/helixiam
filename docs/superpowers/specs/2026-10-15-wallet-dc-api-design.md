# EUDI wallet over the W3C Digital Credentials API (`dc_api` / `dc_api.jwt`)

Status: implemented on `feat/wallet-dc-api` (2026-10-15). No human was available; every decision below was taken by
the implementer and is recorded here (marked **D1…D12**).

## Why

ROADMAP.md (Post-1.0, wallet) lists "the W3C Digital Credentials API (`dc_api`/`dc_api.jwt`) as the
ecosystem-recommended cross-device path (today only redirect same-device and QR cross-device exist, and ARF guidance
recommends against the latter for conformant EU wallets — see `docs/eudi-wallet.md` §8)". HAIP 1.0 §5.2 makes the DC
API the HAIP way to present over the web, with `dc_api.jwt`.

## Spec points this design rests on (read 2026-10-15)

OpenID4VP 1.0 final, Appendix A and B.2.6.2; HAIP 1.0 final §5, §5.2; W3C Digital Credentials (editor's draft).

- **Protocol identifiers** (A.1): `openid4vp-v1-unsigned`, `openid4vp-v1-signed`, `openid4vp-v1-multisigned`.
  JS: `navigator.credentials.get({digital: {requests: [{protocol, data}]}})`; the result is a `DigitalCredential`
  with `protocol` and `data`. `DigitalCredential.userAgentAllowsProtocol(p)` exists for feature detection.
- **Request** (A.2): `response_type`, `response_mode`, `nonce`, `client_metadata`, `dcql_query` (+ `client_id`,
  `request`, `transaction_data`, `verifier_info`). **No `response_uri`, `redirect_uri` or `state`** ("since the state
  parameter is not defined for the DC API, the Verifier cannot expect it to be included in the response").
  `response_mode` is `dc_api` (plain) or `dc_api.jwt` (encrypted per §8.3).
- **Unsigned** (A.3.1): the parameters are the members of `data`; `client_id` MUST be omitted.
- **Signed** (A.3.2.1): `data = {request: <JWS compact>}`; the request object MUST carry `client_id` and
  **`expected_origins`** (A.2: REQUIRED for signed requests; the wallet compares it to the origin the platform gives
  it and refuses on mismatch).
- **Response** (A.4): `data` holds the Authorization Response parameters (`vp_token`, or `response` for `dc_api.jwt`),
  or `{error}`. **The audience is the origin prefixed with `origin:`**, even for signed requests: the SD-JWT KB-JWT
  `aud` MUST be `origin:<Origin>` (B.3.6 / B.2 notes the same), never the `client_id`. The reserved `origin:` client_id
  prefix MUST NOT be sent in requests (§5.9.3).
- **mdoc SessionTranscript over the DC API** (B.2.6.2): `[null, null, OpenID4VPDCAPIHandover]` with
  `OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", sha256(cbor(OpenID4VPDCAPIHandoverInfo))]` and
  `OpenID4VPDCAPIHandoverInfo = [origin (tstr, no "origin:" prefix), nonce (tstr), jwkThumbprint (bstr) / null]`;
  the thumbprint is the RFC 7638 SHA-256 thumbprint of the encryption key for `dc_api.jwt`, `null` for `dc_api`. The
  spec gives a byte-exact example (origin `https://example.com`) that our unit test reproduces.
- **HAIP §5.2**: the Verifier MUST use the DC API (or a platform equivalent) and **MUST use `dc_api.jwt`**; it must
  support at least one of unsigned/signed/multi-signed. §5: signed requests use `x509_hash`; ECDH-ES P-256,
  `A128GCM` and `A256GCM` listed; ephemeral per-request encryption keys.

## Decisions

**D1 — Opt-in per provider, nested `dcApi.*` settings.** A wallet connection gets
`dcApi.enabled` (default `false`), `dcApi.request` (`signed` default, or `unsigned`) and `dcApi.expectedOrigins`
(JSON list; empty = the origin of `IDP_BASE_URL`). Opt-in keeps every existing connection byte-identical and the
merge with `feat/wallet-verify-only` small. A list-valued `invocation` setting was considered and not chosen: the QR
and same-device paths stay always on as the fallback, so only the DC API needs a switch.

**D2 — Encryption follows the existing `responseMode`.** `direct_post.jwt` ⇒ `dc_api.jwt`; the dev-only
`direct_post` ⇒ `dc_api`. No new setting, and HAIP's "MUST use `dc_api.jwt`" holds outside `dev` automatically
(`direct_post` is already refused outside dev). The same per-transaction ephemeral P-256 key and the same
`client_metadata` (`jwks`, `encrypted_response_enc_values_supported` = A128GCM, A256GCM, `vp_formats_supported`) are
used.

**D3 — Signed requests by default (`openid4vp-v1-signed`, JWS compact).** Same signer, `x5c` and `client_id`
(`x509_hash` by default, HAIP §5) as the redirect request object; claims: `response_type`, `client_id`,
`response_mode`, `nonce`, `dcql_query`, `client_metadata`, `expected_origins`, `aud=https://self-issued.me/v2`, `iat`,
`exp`. No `response_uri`, no `state`, no `wallet_nonce`. Unsigned (`openid4vp-v1-unsigned`) sends the same parameters
minus `client_id`/`aud`/`iat`/`exp`/`expected_origins`. Multi-signed is not implemented (HAIP needs only one).

**D4 — The expected origins come from configuration only — never from the request.** The set is
`dcApi.expectedOrigins` or, when empty, the origin of `idp.base.url`. The validator accepts only serialised origins
(`https://host[:port]`, lower-case, no path/query/fragment/userinfo; `http://localhost`/`127.0.0.1` in `dev` only),
at most 10, no duplicates. Each configured origin's host must be the `IDP_BASE_URL` host or listed in
`HELIX_ALLOWED_HOSTS` (the server would refuse to serve the login page on any other host, so such an origin could
never be the page's real origin). The `Origin` header, the page URL and anything in the wallet's answer are never
used to choose it.

**D5 — Origin binding is verified, not trusted.** The response is accepted only when its holder binding names one of
the expected origins:
- SD-JWT VC: KB-JWT `aud` must equal `"origin:" + o` for some expected origin `o` (else `AUDIENCE_MISMATCH`). A
  response bound to the `client_id` (a redirect-flow presentation replayed into the DC API endpoint) is refused the
  same way.
- mdoc: DeviceAuth must verify over the DC API SessionTranscript of some expected origin (tried in order; the set is
  small and bounded), else `HOLDER_BINDING_INVALID`. A redirect-flow DeviceResponse cannot verify (different
  handover).
The redirect endpoint keeps its own context (no DC API origins), so a DC API presentation cannot be replayed into
`/oid4vp/<alias>/response/<id>` either.

**D6 — Transaction lifecycle: a new flow `DC_API`, no schema change.** `WalletTransaction.Flow` gains `DC_API`
(fits `wallet_transaction.flow varchar(16)`; no constraint). The browser asks for the DC API request without changing
the transaction (it must still be `CREATED`), so a user who cancels the browser's credential sheet can still scan the
QR code. A new store transition `claimDcApiResponse(transactionId)` moves `CREATED → RESPONSE_RECEIVED` with
`flow = DC_API` atomically (in-memory CAS, one SQL `UPDATE … WHERE status='CREATED'`, one Redis Lua script); it is the
single-use gate: a second post, or a post after a wallet fetched the QR/same-device request, finds no `CREATED`
transaction and is refused as `REPLAY`. `complete` accepts `DC_API` without a code (like cross-device), and
`issueResponseCode` serves `CROSS_DEVICE` and `DC_API`. No Flyway migration is needed.

**D7 — Endpoints, browser-bound and CSRF-protected.** Both live under the wallet page (`/realms/<realm>/broker/<alias>/
wallet/dc-api/...`), so they get the page's session, the strict login CSP, the per-browser binding check (the
session's `BrowserBinding` must hash to the transaction's, constant time; anything else is a bare 404) and Spring
Security's CSRF check (`X-XSRF-TOKEN` header, double-submit cookie; these paths are *not* CSRF-exempt):
- `POST …/wallet/dc-api/request?tx=` → `200 {"protocol": "...", "data": {...}}` (no-store). `404` when DC API is off
  for the provider, the transaction is not this browser's/realm's/provider's, or it is no longer `CREATED`.
- `POST …/wallet/dc-api/response?tx=` with `application/json` `{"protocol": "...", "data": {...}}` (body limit: the
  same 256 KiB wallet filter now also covers this path) → verified: `200 {"status":"COMPLETED","next":"<callback with
  a fresh response code>"}`; a wallet error object: `200 {"status":"FAILED","reason":"declined"|"technical"}`;
  refused: `400 {"status":"FAILED","reason":<plain-language class>}`; wrong browser/tx: `404`. `protocol` must be the
  one the server offered. The specific check is logged and audited, never returned.
The code goes straight to the bound browser, which follows `next` to the broker callback; redemption is unchanged
(code + session state + browser binding, single use).

**D8 — Progressive enhancement in the login page.** `wallet-dcapi.js` (static, CSP-safe) runs only when
`window.DigitalCredential` exists, `navigator.credentials.get` exists, and
`DigitalCredential.userAgentAllowsProtocol(protocol)` (when present) allows the configured protocol. Only then is a
"Use a wallet (this device or a nearby phone)" button revealed. Without support nothing changes: the QR code and
"Open wallet app" stay as they are. If the user cancels the browser sheet (`AbortError`/`NotAllowedError`), the page
says so and the QR/same-device options remain usable (the transaction was not consumed). The page passes the CSRF
token in a data attribute.

**D9 — Console.** The wallet connection wizard (step "Policies") gets a "Digital Credentials API" section: an on/off
switch, signed/unsigned radio cards (signed recommended, HAIP), and an expected-origins list editor (empty = the
server's own origin, shown as a hint). Client validation mirrors the server's (pure, TDD-tested). EN + NL strings;
the review step shows the setting.

**D10 — Audit.** DC API failures emit the existing `WALLET_LOGIN_FAILURE` event with an extra detail
`invocation=dc_api`; successes are audited, as today, when the browser's code is redeemed (`WALLET_LOGIN_SUCCESS`,
correlated by `transactionId`). Server logs record `flow=DC_API`.

**D11 — `x509_san_dns` with the DC API.** The redirect rule "response_uri host must equal clientIdHost" does not apply
(no `response_uri`, A.3 and §5.9.3 "unless the interaction is using the DC API"), so the DC API request is built for
either client_id scheme.

**D12 — Not in scope.** Multi-signed requests (`openid4vp-v1-multisigned`), `transaction_data`, `verifier_info`
(registration certificate), the ISO `org-iso-mdoc` protocol (ISO 18013-7 Annex C), native-app callers.

## Tests

- `SessionTranscriptsTest`: the B.2.6.2 example byte for byte (handover info, handover, SessionTranscript).
- `AuthorizationRequestFactoryTest`: signed DC API request (claims, no `response_uri`/`state`, `expected_origins`,
  signature + `x5c`), unsigned request (no `client_id`).
- Verifier tests: SD-JWT KB-JWT `aud=origin:` accepted only for an expected origin; mdoc DeviceAuth over the DC API
  transcript; redirect-bound presentation refused in DC API context and vice versa.
- Store contract (`AbstractWalletTransactionStoreTest`, all three stores): `claimDcApiResponse` single use, refused
  after a request fetch, complete/issue code for `DC_API`.
- `WalletDcApiFlowE2eTest` (real HTTP, in-repo test wallet extended with DC API responses): signed and unsigned,
  SD-JWT and mdoc happy paths; origin mismatch, replay, another browser's transaction, missing CSRF, protocol
  mismatch all refused; QR still usable after a cancelled DC API attempt.
- Validator + console validation tests for `dcApi.*`.
