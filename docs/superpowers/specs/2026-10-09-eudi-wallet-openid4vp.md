# Feature request: EUDI Wallet login via OpenID4VP (verifier / relying-party role)

| | |
|---|---|
| **Component** | `helix-iam-server` (+ `helix-dashboard`, `helix-sandbox-rp`, `docs/`) |
| **Type** | New federation provider type |
| **Target maturity at merge** | `Experimental` in `docs/FEATURES.md` |
| **Working title / ticket** | `E12 — EUDI Wallet (OpenID4VP)` *(renumber to match the project's epic numbering)* |
| **Licence of new code** | Apache-2.0, with the standard `Copyright 2026 HelixIAM contributors` / `SPDX-License-Identifier: Apache-2.0` header |

---

## 0. Instructions for the implementing agent

Read this whole document before writing code. Then, **before changing anything**, read these files to learn the project's conventions. Follow those conventions over anything in this document that conflicts with them, and list every such conflict in your PR description.

- `helix-iam-server/src/main/java/io/helixiam/authorization/federation/spi/IdentityProvider.java`
- `.../federation/spi/BrokeredIdentity.java`, `IdpMetadata.java`, `AttributeMapper.java`
- `.../federation/FederationProviderFactory.java` (both `build(...)` and `fromStored(...)`)
- `.../federation/FederationProviderProperties.java`, `IdentityProviderRegistry.java`, `IdentityBroker.java`, `FederatedLoginCompleter.java`, `AccountLinkingPolicy.java`, `PresentedProvider.java`
- `.../federation/eid/*` — this is the closest existing analogue: `EidSamlIdentityProvider`, `EidProviderConfig`, `EidLevelOfAssurance`, `EidScheme`, `EidAssertionValidator`
- `.../federation/saml/SamlAssertionReplayCache.java` and `InMemorySamlAssertionReplayCache.java` (replay-protection pattern)
- `.../security/flow/FederationBrokerController.java` (`/broker/{alias}` and `/broker/{alias}/callback`)
- `helix-iam-server/src/main/resources/templates/` (Thymeleaf login templates and `fragments/`)
- `helix-iam-server/ADAPTERS.md`, `VENDOR-MAP.md`, `SECURITY-REVIEW.md`, `DEFERRED-SECURITY-WORK.md`
- `docs/FEATURES.md`, `ROADMAP.md`, `CONTRIBUTING.md`
- The matching tests under `src/test/java/.../federation/eid/` (test style, fixtures, naming)

Work in the phases of §12. Each phase must compile, pass the full existing test suite, and add its own tests before you start the next. Do not refactor unrelated code. Do not weaken any existing security default.

The protocol specifications are the source of truth, not this document. Where this document paraphrases a spec, verify against the spec text (§14) and follow the spec. Field names, CBOR structures and handover formats changed several times between drafts, so check every one against the **final 1.0** texts. Never copy them from blog posts or older drafts.

---

## 1. Background and motivation

Under eIDAS 2.0 (Regulation (EU) 2024/1183), every EU member state must offer at least one **European Digital Identity Wallet (EUDIW)** to citizens by **24 December 2026**. Regulated relying parties (banks, insurers, telecoms, energy, very large online platforms) must accept it roughly a year later. Every wallet is required to speak:

- **OpenID for Verifiable Presentations 1.0 (OpenID4VP)**: the verifier/relying party requests credentials and the wallet presents them.
- **OpenID4VC High Assurance Interoperability Profile 1.0 (HAIP)**: pins the options of OpenID4VP down to an interoperable, high-assurance subset.
- Two credential formats: **IETF SD-JWT VC** (`dc+sd-jwt`) and **ISO/IEC 18013-5 mdoc** (`mso_mdoc`).
- The mandatory first credential, the **PID (Person Identification Data)**, the digital equivalent of the national ID card, at assurance level **high**.

HelixIAM currently supports eIDAS only through the **eIDAS 1.0 SAML node** route (`federation/eid`, `EidScheme.EIDAS`). It has **no OpenID4VP, OpenID4VCI, SD-JWT VC or mdoc support**. The marketing site says "eIDAS built in". Once national wallets go live, buyers will read that as "EUDI Wallet supported", and today that claim is false.

**Goal:** make HelixIAM a standards-conformant **OpenID4VP verifier** that brokers an EUDI Wallet presentation into a normal Helix login (session plus OIDC/SAML tokens for downstream apps), exactly as the existing DigiD/eIDAS connectors broker a SAML assertion. Downstream applications must not need to know anything about wallets.

---

## 2. Scope

### 2.1 In scope (this feature)

1. A new federation provider protocol, `eudi-wallet` (alias protocol names: `openid4vp`, `wallet`), implementing `IdentityProvider`.
2. **Verifier endpoints**: request object (`request_uri`), `direct_post` / `direct_post.jwt` response endpoint, browser status polling.
3. **Flows:**
   - Same-device: browser and wallet on the same phone, using `openid4vp://` invocation and a `redirect_uri` back to Helix.
   - Cross-device: desktop browser shows a QR code, the phone wallet scans it, and the browser polls for completion.
4. **Credential verification** for:
   - SD-JWT VC (`dc+sd-jwt`): issuer signature, disclosures, key binding (KB-JWT), validity, status.
   - mdoc (`mso_mdoc`): IssuerAuth / MSO, value digests, DeviceAuth over the OpenID4VP session transcript, validity, status.
5. **Query language: DCQL** (Digital Credentials Query Language). DIF Presentation Exchange is **not** to be implemented.
6. **Trust:** X.509 trust anchors for credential issuers (PID providers), configured per provider, plus revocation via **Token Status List**.
7. **Verifier authentication:** signed request objects (JAR) with an X.509 access certificate, using client identifier prefix `x509_san_dns` (required) and `x509_hash` (required if HAIP 1.0 requires it; check).
8. **Encrypted responses** (`direct_post.jwt`, JWE) as HAIP requires.
9. **PID → `BrokeredIdentity` mapping**, configurable attribute mapping, and **level of assurance** (`high`) integrated with the existing LoA enforcement.
10. **Admin console** support for creating and editing the provider (`helix-dashboard`).
11. **Sandbox RP** demo (`helix-sandbox-rp`) plus documentation.
12. Tests: unit, integration with an in-repo **test wallet**, and a documented manual run against the OpenID Foundation conformance suite.

### 2.2 Out of scope (explicitly)

- Acting as a **wallet** or as a **credential issuer** (OpenID4VCI). These may come later and get separate feature requests.
- **Proximity** presentation (ISO 18013-5 over NFC/BLE).
- DIF Presentation Exchange.
- Automatic ingestion of EU **trusted lists** (ETSI TS 119 612 LoTL). Phase 4 covers this as a *stretch* goal; the baseline is manually configured PEM anchors.
- Qualified electronic signatures/seals via the wallet.
- Registering HelixIAM itself with a national RP registrar. That is an operator task; we only consume the certificate it yields.

---

## 3. Glossary

| Term | Meaning |
|---|---|
| **Wallet** | The holder's EUDI Wallet app (wallet unit). |
| **Verifier / RP** | HelixIAM in this feature. |
| **PID** | Person Identification Data credential, issued by a member-state PID provider. |
| **(Q)EAA** | (Qualified) electronic attestation of attributes, i.e. any other credential (diploma, mandate, licence). |
| **DCQL** | Digital Credentials Query Language, the query syntax inside an OpenID4VP request. |
| **JAR** | JWT-Secured Authorization Request (RFC 9101), the signed request object. |
| **Access certificate** | X.509 certificate issued to an RP by the member-state registrar, used to sign request objects. |
| **KB-JWT** | Key Binding JWT that proves possession of the holder key in an SD-JWT presentation. |
| **MSO** | Mobile Security Object, the issuer-signed digest structure in an mdoc. |
| **Transaction** | One verifier-side presentation attempt (Helix-internal concept, §6). |

---

## 4. User stories

1. **End user, desktop:** On the Helix login page I click *"Log in with EU Digital Identity Wallet"*, scan a QR code with my phone's wallet, approve the requested data, and my desktop browser logs me in automatically.
2. **End user, phone:** On my phone I tap the same button, my wallet app opens, I approve, and I'm returned to the browser, logged in.
3. **Realm admin:** In the console I add an "EUDI Wallet (OpenID4VP)" identity provider. I upload the verifier access certificate and key, add the trusted PID-issuer CA certificates, choose which PID attributes to request, and choose how wallet users are linked to Helix accounts.
4. **Application developer:** My app keeps using plain OIDC against Helix. The ID token carries the mapped claims (e.g. `given_name`, `family_name`, `birthdate`) and `acr` reflecting assurance level *high*. I do nothing wallet-specific.
5. **Security officer:** Every wallet login is in the audit log with the credential format, issuer, verification result, and status-list result. Failed verifications are logged with a reason code. No raw PID data appears in logs.

---

## 5. Architecture and fit with the existing SPI

### 5.1 Key insight: the existing SPI works unchanged

`IdentityProvider.start()` returns a `RedirectResponse` and `callback()` receives parameters. OpenID4VP delivers the actual response **server-to-server** (wallet → `response_uri`), not via the browser, so the provider works like this:

- `start(ctx)` creates a **transaction** (§6) and redirects the browser to a **Helix-hosted wallet page**, `GET /broker/{alias}/wallet?tx={transactionId}`. That page shows the QR code and/or the same-device button.
- The wallet fetches the signed request object from `request_uri` and posts its response to `response_uri`. Both are new endpoints handled by a new controller, not by the SPI.
- After successful verification, the browser is sent to the **existing** `/broker/{alias}/callback?response_code=…&state=…`:
  - Same-device: via the `redirect_uri` that Helix returns to the wallet from the `direct_post`.
  - Cross-device: via the polling page.
- `callback(ctx)` redeems the one-time `response_code` and returns the already-verified `BrokeredIdentity`.

If, after reading the code, you conclude the SPI *must* change, stop and record the reason in the PR description. Prefer a backward-compatible addition, such as a default method, over modifying existing signatures.

### 5.2 Components

New package: `io.helixiam.authorization.federation.wallet`

| Class | Responsibility |
|---|---|
| `WalletProviderConfig` (record) | Provider settings (§9). Follow the `EidProviderConfig` style. |
| `WalletIdentityProvider` implements `IdentityProvider` | `metadata()`, `start()` (create transaction, redirect to wallet page), `callback()` (redeem `response_code` → `BrokeredIdentity`), `logout()` (no-op; wallets have no SLO). |
| `WalletTransaction` (record) + `WalletTransactionStore` (interface) | Transaction state machine (§6). |
| `RedisWalletTransactionStore` | Production store (Redis is already a dependency; respect TTL). |
| `InMemoryWalletTransactionStore` | Tests and single-node dev; mirror `InMemorySamlAssertionReplayCache`. |
| `AuthorizationRequestFactory` | Builds the DCQL query and the signed request object (JAR). |
| `DcqlQueryBuilder` | Builds DCQL from config (PID presets and custom credential queries). |
| `VpResponseDecryptor` | Decrypts `direct_post.jwt` (JWE) with the per-transaction ephemeral key. |
| `PresentationVerifier` (interface) | `VerifiedPresentation verify(rawPresentation, VerificationContext)`. |
| `SdJwtVcPresentationVerifier` | SD-JWT VC verification (§7.3). |
| `MdocPresentationVerifier` | mdoc verification (§7.4). |
| `DcqlResultMatcher` | Checks the `vp_token` satisfies the DCQL query (§7.2). |
| `IssuerTrustValidator` | X.509 path validation against configured anchors (§7.5). |
| `TokenStatusListClient` | Fetches, verifies, caches and evaluates status lists (§7.6). |
| `WalletAttributeMapper` | Verified claims → `BrokeredIdentity` + LoA (§8). |
| `WalletSubjectResolver` | Derives the stable `externalSubject` (§8.2). **Security-critical.** |
| `OpenId4VpVerifierController` | New HTTP endpoints (§5.3). |
| `WalletVerificationException` + `WalletErrorCode` (enum) | Typed failures with stable reason codes for audit/UI. |

Wire-up:
- `FederationProviderFactory.build(...)`: iterate `properties.getWallet()`.
- `FederationProviderFactory.fromStored(...)`: add a `case "eudi-wallet", "openid4vp", "wallet" -> …`.
- `inferIconKey(...)`: return `"eudi-wallet"` for these protocols, and add a neutral wallet icon.

**Do not** use the EU flag or any official EU emblem as the icon. Usage of those is restricted.

### 5.3 HTTP endpoints

All paths are relative to the realm base used by the existing broker routes; follow `FederationBrokerController` for the exact prefix.

| Method & path | Caller | Purpose |
|---|---|---|
| `GET /broker/{alias}` | Browser | *Existing.* Calls `start()` → 302 to wallet page. |
| `GET /broker/{alias}/wallet?tx=` | Browser | **New.** Thymeleaf page: QR code (cross-device) + "Open wallet" button (same-device) + (Phase 4) Digital Credentials API. |
| `GET /broker/{alias}/wallet/status?tx=` | Browser (JS poll) | **New.** JSON `{status: PENDING\|COMPLETED\|FAILED\|EXPIRED, next?: url}`. Bound to the browser session (§10). |
| `GET\|POST /oid4vp/{alias}/request/{requestId}` | Wallet | **New.** Returns the signed request object, `Content-Type: application/oauth-authz-req+jwt`. Support `request_uri_method=post` if HAIP requires it; otherwise GET. **Bound to the first flow; the same id may be fetched again until the response arrives** (security requirement 2). |
| `POST /oid4vp/{alias}/response/{responseId}` | Wallet | **New.** `response_uri`; accepts `application/x-www-form-urlencoded` with `response` (JWE) for `direct_post.jwt`, and `vp_token`/`state` or `error` for `direct_post`. Verifies, then returns `200 {"redirect_uri": "..."}` for same-device, or `200 {}` for cross-device. |
| `GET /broker/{alias}/callback?response_code=&state=` | Browser | *Existing.* Calls `callback()`. |

- Exclude the `/oid4vp/**` wallet endpoints from CSRF, since wallets are not the browser.
- Give them their own rate limits and request-size limits (e.g. 256 KB response body; make it configurable).
- They must not require a browser session.

---

## 6. Transaction model

A `WalletTransaction` holds:

```
transactionId        random ≥128-bit, URL-safe   (browser-facing)
requestId            random ≥128-bit             (in request_uri, wallet-facing)
responseId           random ≥128-bit             (in response_uri, wallet-facing)
realmId, providerAlias
helixState           the broker's anti-forgery state from AuthnRequestContext
browserBinding       hash of a value bound to the browser session (§10)
nonce                random ≥128-bit, sent in the request, checked in KB-JWT / mdoc transcript
responseEncryptionKey  ephemeral EC P-256 key pair (private part never leaves the server)
dcqlQuery            the exact DCQL sent
flow                 SAME_DEVICE | CROSS_DEVICE   (decided when the wallet fetches the request — see below)
status               CREATED → REQUEST_FETCHED → RESPONSE_RECEIVED → VERIFIED | FAILED | EXPIRED → REDEEMED
responseCode         one-time code, set on VERIFIED, ≥128-bit
verifiedIdentity     BrokeredIdentity + LoA + audit summary (no raw credential)
failureCode          WalletErrorCode
createdAt, expiresAt TTL default 300 s (configurable 60–900)
```

Rules:
- Every state transition is **atomic** (compare-and-set). In Redis, use a Lua script or `WATCH/MULTI`.
- The request object can be fetched **once**. A response can be accepted **once**. A `response_code` can be redeemed **once**, only together with the matching `helixState`, and only from the bound browser session.
- Expired transactions are rejected everywhere with `EXPIRED`.
- Same-device vs cross-device: generate both the QR payload and the same-device link from the same transaction. In the `direct_post` handler, return a `redirect_uri` **only** when the transaction was started by the same-device button. Track which button was used with a separate `requestId` per invocation path, or a flag set when the wallet page records the click. The spec rationale: in cross-device flows the verifier must not hand the wallet a redirect that would complete the session on the wrong device. Document your chosen mechanism.
- Never store the raw `vp_token`, disclosures or PID values in the transaction after verification. Store only the mapped `BrokeredIdentity` and an audit summary.

---

## 7. Protocol and verification requirements

### 7.1 Authorization request

- Invocation URL (QR / same-device link): `openid4vp://?client_id={client_id}&request_uri={request_uri}` (+ `request_uri_method=post` if used).
  - Make the scheme configurable: some national wallets register `eudi-openid4vp://` or `haip://`. Check the HAIP 1.0 recommendation and the target wallets.
- `client_id` uses the **`x509_san_dns:`** prefix, with the DNS name matching a SAN of the access certificate. Support **`x509_hash:`** as an alternative (prefix plus base64url SHA-256 of the DER leaf certificate) if HAIP lists it.
- Request object (JWS):
  - Header: `typ: oauth-authz-req+jwt`, `alg` (ES256 required; allow ES384/ES512), `x5c` = access certificate chain (leaf first, **without** the root).
  - Claims: `response_type=vp_token`, `client_id`, `response_mode=direct_post.jwt` (default) or `direct_post` (config, *dev only*), `response_uri`, `nonce`, `state`, `dcql_query`, `client_metadata`, `aud` (per spec for the static/dynamic discovery case), `iat`, `exp`.
- `client_metadata` must contain:
  - `jwks`: the ephemeral **encryption** public key, `use: enc`, `alg` per HAIP (e.g. `ECDH-ES`), plus a `kid`.
  - The supported `encrypted_response_enc_values_supported` (or the 1.0 equivalent field; verify the name).
  - `vp_formats_supported` for `dc+sd-jwt` and `mso_mdoc` with the allowed algorithms.
- Optional, behind config: include the **registration certificate** / attestation of the RP's registered attribute entitlements, if the national scheme issues one (`verifier_info` / `verifier_attestations` in OpenID4VP 1.0; verify the name). Wallets may warn users when an RP requests more than it registered for.

### 7.2 DCQL and response shape

- Build DCQL from config.
- PID preset: one credential query per enabled format:
  - `dc+sd-jwt` with `meta.vct_values` = configured PID VCT(s).
  - `mso_mdoc` with `meta.doctype_value` = configured PID doctype.
  - Use `credential_sets` so **either** format satisfies the request.
- Request **only** the claims the admin selected (data minimisation is a legal requirement; see §11).
- Expected `vp_token`: a JSON object keyed by the DCQL credential-query `id`; each value is an **array** of presentations (OpenID4VP 1.0). Reject any other shape.
- `DcqlResultMatcher` must check that:
  - every required credential query is satisfied;
  - each presentation matches the format, `vct`/`doctype` and requested claims of its query;
  - **no** claims were disclosed beyond those requested. Over-disclosed claims are dropped and logged, not used.

### 7.3 SD-JWT VC verification (`dc+sd-jwt`)

For each presentation, in this order, failing closed:

1. Parse `<issuer-JWT>~<disclosure>~...~<KB-JWT>`. Reject if the KB-JWT is missing; holder binding is required.
2. Issuer-signed JWT:
   - `typ` is `dc+sd-jwt` (accept legacy `vc+sd-jwt` only behind a config flag, default **off**).
   - `alg` is in the allow-list (ES256/ES384/ES512, PS256+; never `none`, never HS*).
3. Resolve the issuer key **via `x5c`** in the header and validate the chain against the configured anchors (§7.5).
   - Do **not** fetch issuer metadata from `iss` unless explicitly enabled; trust must come from configured anchors.
   - Verify the signature.
4. Validate `iss`, `vct` (must equal a configured value), `iat`, `nbf`, `exp`, with clock skew ≤ 60 s (configurable).
5. Disclosures: recompute each digest with `_sd_alg` (default `sha-256`; allow-list), and match it against `_sd` / array `...` entries.
   - Reject duplicate digests, disclosures not referenced by the payload, and disclosures that would overwrite plain claims.
   - Handle recursive disclosures.
6. KB-JWT:
   - `typ: kb+jwt`.
   - Signature verified with `cnf.jwk` from the issuer-signed JWT.
   - `aud` equals our `client_id`; `nonce` equals the transaction nonce.
   - `iat` within the window.
   - `sd_hash` equals the hash of the presented issuer-JWT plus disclosures, per spec.
7. Status: if a `status.status_list` claim is present, evaluate it (§7.6). If absent and the provider config sets `requireStatus=true`, reject.
8. Output: the disclosed claims as a JSON object, plus issuer certificate subject and serial for audit.

### 7.4 mdoc verification (`mso_mdoc`)

Each presentation is a base64url-encoded CBOR `DeviceResponse`.

1. Parse with strict CBOR limits: max nesting, max item count, max byte length.
2. For each `Document`, check `docType` equals the configured doctype, and `status` is 0.
3. IssuerAuth (COSE_Sign1):
   - Validate the `x5chain` against the anchors (§7.5) and verify the signature.
   - Decode the MSO and check `docType` matches.
   - Check the `validityInfo` window (`validFrom`, `validUntil`, also `signed` ≤ now).
4. For every returned `IssuerSignedItem`, recompute the digest (`digestAlgorithm`) and compare it with `valueDigests[namespace][digestID]`. Reject on mismatch or missing entry.
5. DeviceAuth:
   - Build the **SessionTranscript** exactly as OpenID4VP 1.0 Annex B specifies for redirect-based / `direct_post` flows: `[null, null, OpenID4VPHandover]`, where the handover hashes `client_id`, `nonce`, the JWK thumbprint of the response-encryption key (or null when unencrypted) and `response_uri`. **Verify the exact structure in the final spec; it changed between drafts.**
   - Verify `deviceSignature` with `deviceKeyInfo.deviceKey` from the MSO. If `deviceMac` is used, support it only if HAIP requires it; otherwise reject.
6. Status: evaluate the MSO status reference (`status` → Token Status List) as in §7.6.
7. Output: claims as `namespace → { elementIdentifier → value }`, normalised to JSON (dates as ISO-8601 strings, bytes as base64url), plus issuer certificate details.

### 7.5 Issuer trust

- Per provider: a list of **trust anchors** (PEM CA certificates of PID providers / their CAs), plus optional pinned intermediate certificates.
- Use PKIX path validation (`java.security.cert.CertPathValidator` or BouncyCastle; BC 1.86 is already a dependency) with:
  - key usage / extended key usage checks per the ETSI/ISO profile;
  - validity checks;
  - CRL/OCSP checking **configurable** (default: soft-fail with a warning logged; `hardFail` option).
- The trust store is cached and reloaded on provider refresh (`FederationStoreRefresher`).
- Phase 4 (stretch): an `EuTrustedListSource` that downloads and verifies the EU **List of Trusted Lists** and national lists (ETSI TS 119 612), extracts PID-provider anchors, and caches them with a signature-verified refresh. Until then, document clearly that anchors are manual.

### 7.6 Token Status List

- Implement the IETF *Token Status List* draft (`status.status_list.{idx, uri}`), with the status list token served as JWT (`application/statuslist+jwt`) and optionally CWT for mdoc.
- Verify the status list token signature against the **same trust anchors** as the credential issuer. Check `sub` equals the `uri` and that the token is fresh (`exp`/`ttl`).
- Decompress (zlib/DEFLATE) with a size cap, read `bits`, and evaluate index `idx`: `0x00` = VALID; anything else fails with `CREDENTIAL_REVOKED` or `CREDENTIAL_SUSPENDED`.
- Cache by URI with respect for `ttl` (max cache configurable, default 15 min).
- Use an outbound HTTP client with timeouts (connect 3 s, read 5 s) and an allow-list option for status hosts.
- Behaviour when unreachable is configurable (`FAIL_CLOSED` default for LoA high, `FAIL_OPEN_WITH_AUDIT` optional).

### 7.7 Response decryption (`direct_post.jwt`)

- Use the per-transaction ephemeral key.
- Allow-list `alg` (`ECDH-ES`) and `enc` (`A128GCM`, `A256GCM`, per HAIP); reject anything else.
- `kid` must match the transaction key.
- After decryption, the inner payload holds `vp_token` (and `state` when sent). Check `state` equals the transaction state.
- Destroy the private key when the transaction ends.

### 7.8 Wallet error responses

If the wallet posts `error` (e.g. `access_denied`, `invalid_request`), mark the transaction `FAILED` with a mapped `WalletErrorCode`. The browser then shows a friendly message and a retry button. Never echo `error_description` unescaped.

---

## 8. Identity mapping

### 8.1 Attribute mapping

- Default mapping, from the PID Rulebook claim names (the SD-JWT and mdoc names differ; e.g. `birthdate` vs `birth_date`). **Take the canonical names from the current ARF PID Rulebook (Annex 3.1) and record the version used in a code comment.**
  - `given_name` → `given_name`, `family_name` → `family_name`
  - `birthdate` / `birth_date` → `birthdate`
  - `nationalities` / `nationality` → `nationalities`
  - optional: `place_of_birth`, `address.*`, `issuing_country`, `issuing_authority`, `age_over_18`
- Reuse `AttributeMapperRules` / `DefaultAttributeMapper` for admin-defined overrides. Don't build a parallel mapping mechanism.
- `email` / `emailVerified`: PID contains no email. Set `email=null`, `emailVerified=false`, and make sure the existing linking/JIT code handles that. If it doesn't, extend it in a backward-compatible way.
- Add an attribute `helix_wallet_format` (`dc+sd-jwt`|`mso_mdoc`) and `helix_wallet_issuer` (issuer certificate subject DN) for auditing and claim mapping.

### 8.2 External subject (security-critical: read carefully)

The PID **does not guarantee a stable, unique identifier**. `personal_administrative_number` is optional and member-state dependent. A naïve choice here enables account takeover. Implement `WalletSubjectResolver` with an explicit, admin-chosen strategy (no silent default in production):

| Strategy | `externalSubject` | Notes |
|---|---|---|
| `ADMINISTRATIVE_NUMBER` | `sha256(issuing_country ‖ ":" ‖ personal_administrative_number)` | Strongest. **Fail** the login if the claim is absent. |
| `ATTRIBUTE_TUPLE` | `sha256(issuing_country ‖ family_name ‖ given_name ‖ birthdate ‖ place_of_birth?)` (normalised) | Weak, collision-prone. Allowed only with an explicit `acknowledgeWeakSubject=true` flag; shows a warning in the console. |
| `NONE` | none | Wallet used only for **verification/step-up of an already logged-in user** (Phase 3). Cannot create or link accounts. |

- Hash with a **per-realm secret pepper** (HMAC-SHA-256), so the stored subject does not leak the national number. Store the pepper the same way other realm secrets are stored.
- Account linking must go through the existing `AccountLinkingPolicy`. **Never auto-link to an existing local account by matching name or birthdate.**

### 8.3 Level of assurance

- Extend LoA handling so a wallet login with a PID verified from a trusted PID-provider anchor yields **eIDAS LoA high** (`http://eidas.europa.eu/LoA/high`). Consider adding `EidScheme.EUDI_WALLET` with its own ladder, or reuse the eIDAS ladder; justify the choice in the PR.
- The provider config may set `minimumLoa`, as for eID providers.
- Propagate the LoA into the issued token's `acr` the same way the eID connectors do today (find and follow that code path).

---

## 9. Configuration

Static config (`FederationProviderProperties`, new list `wallet`) and stored config (`fromStored`, flat `Map<String,String>`, JSON-encoded lists where needed) must support:

```yaml
helix:
  federation:
    wallet:
      - alias: eudi-wallet
        displayName: "EU Digital Identity Wallet"
        clientIdScheme: x509_san_dns            # x509_san_dns | x509_hash
        clientIdHost: id.example.eu              # must match a SAN in the access certificate
        accessCertificateChain: |                # PEM, leaf first, no root
          -----BEGIN CERTIFICATE----- ...
        accessCertificateKeyRef: kms://realm/eudi-access-key   # MUST use the existing per-realm KMS/HSM/PKCS#11 key abstraction
        registrationCertificate: null            # optional, see §7.1
        invocationScheme: openid4vp              # openid4vp | eudi-openid4vp | haip | custom
        responseMode: direct_post.jwt            # direct_post only allowed when helix.dev-mode=true
        requestUriMethod: get                    # get | post
        transactionTtlSeconds: 300
        credentialFormats: [dc+sd-jwt, mso_mdoc]
        pid:
          sdJwtVcts: ["urn:eudi:pid:1"]          # verify current value against ARF; make it a list
          mdocDoctype: "eu.europa.ec.eudi.pid.1"
          requestedClaims: [given_name, family_name, birthdate]
        customCredentialQueries: []              # Phase 3: raw DCQL credential queries (EAA)
        trustAnchors: |                          # PEM bundle of PID-provider CAs
          -----BEGIN CERTIFICATE----- ...
        revocationChecking: SOFT_FAIL            # OFF | SOFT_FAIL | HARD_FAIL (X.509 CRL/OCSP)
        statusList:
          required: true
          onUnavailable: FAIL_CLOSED             # FAIL_CLOSED | FAIL_OPEN_WITH_AUDIT
          maxCacheSeconds: 900
          allowedHosts: []                       # empty = any https host
        subject:
          strategy: ADMINISTRATIVE_NUMBER        # ADMINISTRATIVE_NUMBER | ATTRIBUTE_TUPLE | NONE
          acknowledgeWeakSubject: false
        minimumLoa: http://eidas.europa.eu/LoA/high
        clockSkewSeconds: 60
        allowLegacyVcSdJwtTyp: false
```

- Validate config at startup and on store refresh; fail fast with clear messages:
  - certificate SAN matches `clientIdHost`;
  - key matches the certificate;
  - at least one trust anchor;
  - at least one format;
  - `direct_post` is not allowed in production (hook into `ProductionReadinessCheck`).
- The signing key **must** go through the existing per-realm key management (KMS/HSM/PKCS#11). Find that abstraction and reuse it. Do not accept raw private-key PEMs in production mode. A raw PEM is allowed only in dev mode, if the eID connector does the same.

---

## 10. Security requirements (non-negotiable)

1. **Browser binding:** the `status` endpoint and the `callback` only act for the browser session that started the transaction (same cookie/session id, compared by hash). A leaked QR code or `transactionId` must not let an attacker complete someone else's login.
2. **Single use** of `responseId`, `nonce` and `response_code`, enforced atomically (§6). A `requestId` is single use
   per flow: the first fetch binds the transaction to its flow (the other flow's id is refused from then on), the same
   id may be fetched again while the transaction is `REQUEST_FETCHED`, and it is refused once the response has been
   received or the transaction has ended or expired. *Ruling (2026-10-15, after the OpenID Foundation conformance run,
   `docs/compliance/oid4vp-conformance/README.md` D2):* real wallets retry a `request_uri` fetch after a network error,
   and the HAIP certification plan tests it (`request-uri-fetched-twice`). A re-fetch exposes nothing new: it returns the
   same signed request (same nonce, state, response URI, ephemeral key, `iat`, `exp`) to whoever holds the same bearer
   id, and the response stays single use, so it cannot be used to answer twice.
3. **No session fixation:** rotate the Helix session id on successful login, as the existing broker does; verify this.
4. All random identifiers use `SecureRandom` with ≥128 bits.
5. Strict input limits:
   - request body size;
   - CBOR depth/size;
   - number of disclosures (default ≤ 100);
   - JWT size;
   - status-list decompressed size (default ≤ 2 MB);
   - outbound fetch timeouts.
6. Algorithm allow-lists everywhere (JWS, JWE, COSE, digest). Reject `none`, HMAC for issuer/holder signatures, and RSA < 2048.
7. No **SSRF**:
   - status-list URIs must be `https`, are resolved with private/loopback/link-local ranges blocked, and optionally match `allowedHosts`;
   - no other wallet-supplied URL is ever dereferenced.
8. **Logging:**
   - never log `vp_token`, disclosures, PID values, nonces, `response_code` or keys;
   - log transaction id, alias, realm, format, issuer DN, result and `WalletErrorCode`.
   - Emit audit events through the existing audit-log mechanism (`WALLET_LOGIN_SUCCESS`, `WALLET_LOGIN_FAILURE`, `WALLET_STATUS_CHECK_FAILED`).
9. **Clickjacking/CSP:** the wallet page uses the same CSP/frame headers as `login.html`. The QR code is generated server-side as SVG, or with a vetted client library served locally (no CDN).
10. The `direct_post` endpoint returns generic errors to the wallet (spec error codes only) and never reveals internal verification details.
11. Add an entry to `SECURITY-REVIEW.md` describing the threat model of this flow, and to `DEFERRED-SECURITY-WORK.md` for anything consciously postponed (e.g. trusted-list automation, OCSP hard-fail).

---

## 11. Privacy and compliance

- **Data minimisation:** request only the admin-selected claims. The console shows a warning if more than five claims are selected, or if `personal_administrative_number` is requested without the `ADMINISTRATIVE_NUMBER` strategy.
- Store the attributes the realm actually maps to the user profile; discard the rest after mapping.
- The existing GDPR rights tooling must cover wallet-derived attributes (export/delete). Verify this and add tests.
- Document for operators that going live requires:
  1. registration as a relying party with the competent national registrar;
  2. an access certificate from the national access-certificate CA;
  3. requesting only the attributes registered for the stated purpose.

  Mirror the existing honest "bring your own broker agreement" wording.

---

## 12. Delivery phases

### Phase 1: Verification core (no HTTP yet)
- `SdJwtVcPresentationVerifier`, `MdocPresentationVerifier`, `IssuerTrustValidator`, `TokenStatusListClient`, `DcqlResultMatcher`, `VpResponseDecryptor`.
- Library choice, decided and documented in the PR (§13).
- Unit tests with **spec test vectors** (from the IETF SD-JWT, SD-JWT VC and Token Status List drafts, ISO 18013-5 Annex D where available, OpenID4VP examples), plus negative tests for every check in §7.3–§7.7.

### Phase 2: Login flow end-to-end
- `WalletProviderConfig`, `WalletIdentityProvider`, transaction store (Redis plus in-memory), `AuthorizationRequestFactory`, `OpenId4VpVerifierController`, wallet page template (QR, same-device button, polling), factory wiring, `WalletSubjectResolver`, mapping, LoA.
- **In-repo test wallet** (`src/test/.../wallet/testwallet/TestWallet`). It:
  - issues test PID credentials in both formats from a test CA;
  - parses a real request object;
  - builds a correct encrypted response.

  Integration tests drive the full flow through MockMvc or a Spring Boot test for: same-device success, cross-device success, user denies, expired, replayed response, wrong nonce, wrong audience, revoked credential, untrusted issuer, over-disclosure, missing administrative number, and response from a different browser session.

### Phase 3: Admin and developer experience
- `helix-dashboard`: an "EUDI Wallet (OpenID4VP)" provider form following `DESIGN_SYSTEM.md`:
  - certificate/key upload via KMS ref;
  - trust anchor upload with a parsed preview (subject, expiry);
  - claim picker for the PID preset;
  - subject strategy with an inline explanation and warning;
  - format checkboxes.
  - Storybook story plus vitest tests.
- `helix-sandbox-rp`: a demo realm and README walkthrough using the test wallet or the EU reference wallet in test mode.
- Docs:
  - new `docs/eudi-wallet.md` (operator guide: registration, certificates, trust anchors, subject strategy, limitations);
  - `docs/FEATURES.md` row "EUDI Wallet (OpenID4VP verifier) | Experimental | `authorization/federation/wallet` | <test count>";
  - `ROADMAP.md` updated;
  - `CHANGELOG.md`.
- Optional: `customCredentialQueries` for (Q)EAA, and a `NONE` subject strategy that implements **step-up verification for a logged-in user**. Expose this as a separate flow, e.g. a required-action or `acr_values`-triggered step-up; design it to fit the existing `security/flow` machinery and document the design.

### Phase 4: Interop and stretch
- Run the **OpenID Foundation conformance suite** (OpenID4VP 1.0 + HAIP 1.0, verifier tests) and record results in `docs/eudi-wallet.md`. Fix every failure or document it as a known deviation.
- Interop test against the **EU reference wallet** (`eu-digital-identity-wallet` Android/iOS apps, test PID issuer) and at least one national wallet test build, if available.
- **W3C Digital Credentials API** (`navigator.credentials.get` with `digital`), with response modes `dc_api` / `dc_api.jwt` and the origin-based client identifier rules. Feature-detect in the wallet page; fall back to QR/link.
- `EuTrustedListSource` (§7.5).
- Terraform provider: resource support for the new provider type.

---

## 13. Libraries: evaluate, then decide

Prefer mature, maintained, Apache-2.0-compatible libraries; avoid hand-rolling crypto. Candidates:

| Need | Candidates | Notes |
|---|---|---|
| JOSE (JWS/JWE/JWK) | **Nimbus JOSE+JWT** | Likely already on the classpath via Spring Security; check `mvn dependency:tree` and reuse the managed version. |
| SD-JWT VC verify | `eu.europa.ec.eudi:eudi-lib-jvm-sdjwt-kt`; Nimbus + own SD-JWT parser | The EUDI lib is Kotlin (adds kotlin-stdlib). Check licence and that it has a *verifier* API. A small, well-tested own parser on top of Nimbus is acceptable if the lib is a poor fit. |
| mdoc / COSE / CBOR | `org.multipaz` (formerly Google `identity-credential`); `com.authlete:cbor`; `COSE-JAVA` + Jackson CBOR | Must support COSE_Sign1 with x5chain and the 18013-5 structures. |
| X.509 path validation | JDK `CertPathValidator`; BouncyCastle (already present, 1.86) | |
| QR code | `com.google.zxing:core` | Server-side SVG/PNG. |
| Reference implementation to *read*, not copy blindly | `eu-digital-identity-wallet/eudi-srv-verifier-endpoint` (Kotlin, Spring Boot) | Excellent behavioural reference for request objects, transcripts and response handling. Check its licence before copying any code; attribute properly. |

Add any new dependency to `VENDOR-MAP.md`, pin its version in the POM's `<properties>` like the existing pins, and make sure the CI dependency/licence scanning passes.

---

## 14. Normative references (verify current versions before implementing)

- OpenID for Verifiable Presentations **1.0** (final) — openid.net/specs
- OpenID4VC High Assurance Interoperability Profile (**HAIP**) **1.0**
- IETF **SD-JWT** (RFC 9901, or the latest draft if not yet an RFC) and **SD-JWT VC** draft
- IETF **Token Status List** draft (`draft-ietf-oauth-status-list`)
- ISO/IEC **18013-5** (mdoc) and ISO/IEC TS **18013-7** / OpenID4VP Annex B (mdoc over OpenID4VP)
- RFC 9101 (JAR), RFC 7515/7516/7517/7518 (JOSE), RFC 9052 (COSE), RFC 8949 (CBOR), RFC 7638 (JWK thumbprint)
- EUDI Wallet **Architecture and Reference Framework (ARF)**, current version, incl. **PID Rulebook** — github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework
- Commission Implementing Regulations under Regulation (EU) 2024/1183 on PID, protocols/interfaces, relying-party registration and trust frameworks
- OpenID Foundation EUDIW resource hub and conformance suite — openid.net/eudiw_community_page
- W3C Digital Credentials API (Phase 4)

---

## 15. Acceptance criteria

Phase 2 is "done" when **all** of the following hold:

- [ ] A realm admin can configure a wallet provider via YAML **and** via the stored-config path, and it appears on the login page with the wallet icon.
- [ ] Cross-device: QR → test wallet → desktop browser logged in within one poll interval. The ID token contains mapped PID claims and `acr` = LoA high.
- [ ] Same-device: link → test wallet → browser redirected to `/broker/{alias}/callback` → logged in.
- [ ] Both `dc+sd-jwt` and `mso_mdoc` PIDs succeed. Either satisfies the default DCQL `credential_sets`.
- [ ] Each of these is rejected with a distinct `WalletErrorCode`, a friendly UI message and an audit event:
  - tampered issuer signature;
  - untrusted issuer;
  - expired credential;
  - revoked credential (status list);
  - wrong nonce;
  - wrong `aud`;
  - missing KB-JWT / DeviceAuth;
  - replayed response;
  - reused `response_code`;
  - redeem from another browser session;
  - unrequested-claim over-disclosure (claims dropped, not rejected, unless they're mapped);
  - expired transaction;
  - wallet `access_denied`.
- [ ] `direct_post` (unencrypted) is refused when the production readiness check is active.
- [ ] No PID value, token, nonce or key appears in logs at any level. A test asserts this by capturing log output during the happy path.
- [ ] Redis store: concurrent duplicate `direct_post` submissions result in exactly one success (concurrency test).
- [ ] The full existing test suite passes; CodeQL and dependency scanning are clean, or new findings are triaged in `CODEQL-TRIAGE.md`.
- [ ] `docs/eudi-wallet.md`, `docs/FEATURES.md` (Experimental), `CHANGELOG.md`, `VENDOR-MAP.md`, `SECURITY-REVIEW.md` are updated.

Phase 4 adds: a conformance-suite run is documented, with a pass/deviation list.

---

## 16. Open questions for the maintainer (decide before or during Phase 2)

1. **Subject strategy default** for NL deployments: does the NL PID carry `personal_administrative_number` (BSN or a sectoral number)? If not, wallet-only account creation for NL users needs a different design (e.g. the first login via DigiD links the wallet).
2. **LoA modelling:** a new `EidScheme.EUDI_WALLET` vs reuse of the eIDAS ladder.
3. **Kotlin dependencies** (EUDI libs) in a Java-only server: acceptable, or keep it pure Java?
4. **Step-up/verification-only flow** (Phase 3): required-action vs `acr_values` vs a dedicated endpoint.
5. **Website claim:** until Phase 4 interop is done, the site should say "EUDI Wallet (OpenID4VP) — experimental", not "supported".

---

## 17. PR checklist for the implementing agent

- [ ] Read all files listed in §0 before coding.
- [ ] One PR per phase, each green on CI.
- [ ] Every verification step in §7 has at least one positive and one negative test.
- [ ] No new `@SuppressWarnings` or disabled security checks without a comment and a triage entry.
- [ ] PR description covers:
  - library decisions (§13);
  - deviations from this document, with the reason;
  - the spec versions used (with dates);
  - remaining open questions.
- [ ] Commits end with the project's required attribution lines, if any (see `CONTRIBUTING.md`).
