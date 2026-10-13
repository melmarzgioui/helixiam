# EUDI Wallet login via OpenID4VP (verifier) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make HelixIAM a conformant OpenID4VP 1.0 / HAIP 1.0 verifier that brokers an EUDI Wallet PID presentation
(SD-JWT VC or mdoc) into a normal Helix login, so downstream apps keep using plain OIDC/SAML.

**Architecture:** A new federation provider protocol `eudi-wallet` behind the existing `IdentityProvider` SPI. `start()`
creates a server-side *wallet transaction* and redirects the browser to a Helix wallet page (QR + same-device link);
the wallet talks to two new server-to-server endpoints (`request_uri`, `response_uri`); verification happens there;
the browser then lands on the **existing** `/broker/{alias}/callback?response_code=…` and `callback()` redeems the
already-verified identity. Credential verification is a pure-Java core (Nimbus JOSE + Jackson CBOR + BouncyCastle/JDK).

**Tech Stack:** Java 21, Spring Boot 3.5.16, Nimbus JOSE+JWT (managed by Boot, already on the classpath), Jackson
CBOR (direct dep), BouncyCastle 1.86 (direct), ZXing (direct, server-side SVG QR), Redis (Lettuce, direct),
Thymeleaf, Playwright browser harness, React/Vite console.

**Spec:** `docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md` (the feature request). Executors read the spec
AND this plan. The **protocol specifications (§14 of the spec) are normative** over both.

---

## Maintainer decisions (answered 2026-10-09)

| Spec §16 question | Decision |
|---|---|
| 1. Subject strategy | `ADMINISTRATIVE_NUMBER` when the PID carries `personal_administrative_number`. When it does not, the wallet **cannot create an account**; the user links the wallet once from an already-authenticated session (§Task 21). |
| 2. LoA modelling | **Reuse the eIDAS ladder** (`http://eidas.europa.eu/LoA/{low,substantial,high}`). Add `EidScheme.EUDI_WALLET` only as an audit/display tag that delegates to the EIDAS ladder. |
| 3. Kotlin libraries | **Pure Java.** No kotlin-stdlib. Own SD-JWT parser on Nimbus; own minimal COSE_Sign1/MSO handling on Jackson CBOR + JDK/BC crypto. |
| 4. Step-up (verify-only) flow | **Out of this plan.** Separate plan after Phase 2 is proven. Strategy `NONE` is not implemented here. |
| 5. Website claim | "EUDI Wallet (OpenID4VP) — experimental" until the Phase 4 interop run (separate plan). |

## Conflicts with the spec (to repeat in every PR description)

1. **§9 "MUST use the existing per-realm KMS/HSM/PKCS#11 key abstraction"** — none exists. `SigningKeyProvider` returns
   *exported private-key bytes* and only has a software RSA implementation. Task 5 introduces a minimal
   `RealmSigningKeys` abstraction (software keys, DB-encrypted; PKCS#11/KMS as an SPI seam, not implemented).
2. **§8.3 "propagate LoA into `acr` the same way eID connectors do"** — no such path exists; eID LoA is only stored as a
   user attribute at JIT time. Task 3 builds the `acr` path (benefits eID too).
3. **§10.3 "rotate the session id as the existing broker does"** — the existing broker does **not** rotate it. Task 2
   fixes this for all federated logins (security fix).
4. **Provider secrets** — existing IdP config (eID private keys, OIDC client secrets) is stored unencrypted in
   `identity_provider.config_json` and returned unredacted by the admin API. The wallet access key must not repeat
   this. Task 4 fixes it for all providers (security fix).
5. **§16.1 "link" fallback** — linking a PID **without** an administrative number still needs *some* stable subject.
   Task 21 uses the HMAC of the normalised attribute tuple, but **only to match accounts the user explicitly linked
   while authenticated**; it never creates or auto-links accounts. Residual risk (two people with identical tuple, one
   of whom linked) is documented in `SECURITY-REVIEW.md` and gated by `acknowledgeWeakSubject=true`.
6. **IdP registry is keyed by alias, not realm** (`IdentityProviderRegistry.get(alias)`). Wallet transactions store the
   realm and every wallet endpoint re-checks `transaction.realmId == RealmContextHolder.get()`.
7. **Commits:** `CONTRIBUTING.md` requires a DCO `Signed-off-by:` trailer (`git commit -s`). The project owner's rule
   forbids AI attribution trailers (no `Co-Authored-By`, no "Claude"). Use `git commit -s` only.

## Global Constraints

- Every new Java file starts with `/*\n * Copyright 2026 HelixIAM contributors\n * SPDX-License-Identifier: Apache-2.0\n */`.
- New package: `io.helixiam.authorization.federation.wallet` (subpackages `sdjwt`, `mdoc`, `trust`, `status`, `dcql`,
  `transaction`, `web`).
- Protocol strings accepted by `fromStored`: `"eudi-wallet", "openid4vp", "wallet"` (case-insensitive). Icon key
  `"eudi-wallet"`, neutral wallet icon. **Never** the EU flag or any EU emblem.
- Algorithms: JWS `ES256` required, `ES384`/`ES512`/`PS256`+ allowed; never `none`, never `HS*`, RSA ≥ 2048. JWE
  `alg=ECDH-ES`, `enc ∈ {A128GCM, A256GCM}`. SD-JWT `_sd_alg` default `sha-256` (allow-list). COSE `ES256/384/512`.
- Limits (configurable, these defaults): response body 256 KB; JWT 64 KB; disclosures ≤ 100; CBOR depth ≤ 16, items ≤
  10 000, bytes ≤ 256 KB; status-list decompressed ≤ 2 MB; status fetch connect 3 s / read 5 s; clock skew ≤ 60 s;
  transaction TTL 300 s (60–900); status cache max 900 s.
- Identifiers (`transactionId`, `requestId`, `responseId`, `nonce`, `response_code`) are `SecureRandom` ≥ 128 bits,
  base64url, single-use, enforced atomically.
- `direct_post` (unencrypted) only in the `dev` profile; `ProductionReadinessCheck` refuses it otherwise.
- **Never log** `vp_token`, disclosures, PID values, nonces, `response_code`, keys. Log transaction id, alias, realm,
  format, issuer DN, result, `WalletErrorCode`. User-controlled values via `LogSafe.sanitize`.
- Schema changes: BOTH `schema.sql` and a Flyway migration; next free number **V75**.
- Admin API conventions: 400 `{message, fieldErrors}` via `AdminValidationAdvice`; never throw into `/error`; by-id
  lookups scoped to the path realm (404 otherwise).
- DB pool auto-commit is false: test writes go through `TransactionTemplate`.
- Console: design-system kit, **zero inline styles**, full width, validated forms (pure TDD-tested function), a
  Playwright UI/UX review at 1440 and 390, light and dark, before merge.
- Each phase: compile, full suite green (`mvn -B clean verify`), the sql-init run green
  (`mvn -B test -Dhelix.e2e.schema=sql-init -Dtest='*E2eTest,Flyway*Test' -Dsurefire.failIfNoSpecifiedTests=false`),
  before the next phase starts. One PR per phase.
- Every verification step of spec §7 has ≥ 1 positive and ≥ 1 negative test.

## Review Focus

1. **A QR code photographed from someone else's screen** (cross-device, attacker completes the wallet step) must never
   log the attacker's *browser* in: the status poll and `callback` act only for the browser session hash stored on the
   transaction → Task 18 test `statusAndCallback_fromAnotherBrowserSession_areRefused`.
2. **The same wallet response posted twice concurrently** (network retry, two replicas) must yield exactly one
   `VERIFIED` → Task 16 Redis CAS concurrency test with 20 parallel `markResponseReceived` calls.
3. **A PID issued in another member state whose admin number collides numerically with a local one** must not merge
   accounts: subject = HMAC(pepper, `issuing_country ":" number`) → Task 21 test
   `sameNumberDifferentCountry_givesDifferentSubjects`.
4. **A wallet that discloses more claims than requested** (e.g. full address) must have those dropped, never mapped,
   never stored, and only their *names* logged → Task 14 test `overDisclosedClaims_areDroppedAndOnlyNamesLogged`.
5. **A status-list URL pointing at an internal address** (`https://169.254.169.254/…`, `https://localhost/…`) must be
   refused before any connection → Task 10 test `statusListUri_privateAddress_isRefusedWithoutConnecting`.

---

## File structure

```
helix-iam-server/src/main/java/io/helixiam/authorization/
  federation/
    spi/IdpMetadata.java                         MODIFY  add Protocol.WALLET
    FederationProviderFactory.java               MODIFY  build()/fromStored()/inferIconKey()
    FederationProviderProperties.java            MODIFY  List<WalletProviderConfig> wallet
    FederatedLoginCompleter.java                 MODIFY  rotate session id; stamp acr (Tasks 2, 3)
    eid/EidScheme.java                           MODIFY  EUDI_WALLET (delegates to EIDAS ladder)
    eid/EidLevelOfAssurance.java                 MODIFY  EUDI_WALLET → EIDAS ladder
    wallet/
      WalletProviderConfig.java                  record + nested records (§9)
      WalletConfigValidator.java                 startup / refresh / admin validation
      WalletIdentityProvider.java                IdentityProvider impl
      WalletErrorCode.java  WalletVerificationException.java
      VerifiedPresentation.java  VerificationContext.java  PresentationVerifier.java
      trust/IssuerTrustValidator.java  trust/TrustAnchors.java
      sdjwt/SdJwt.java  sdjwt/Disclosure.java  sdjwt/SdJwtVcPresentationVerifier.java
      mdoc/StrictCbor.java  mdoc/CoseSign1.java  mdoc/MobileSecurityObject.java
      mdoc/SessionTranscripts.java  mdoc/MdocPresentationVerifier.java
      status/TokenStatusListClient.java  status/StatusListToken.java
      dcql/DcqlQueryBuilder.java  dcql/DcqlResultMatcher.java
      VpResponseDecryptor.java
      AuthorizationRequestFactory.java
      transaction/WalletTransaction.java  transaction/WalletTransactionStore.java
      transaction/InMemoryWalletTransactionStore.java  transaction/RedisWalletTransactionStore.java
      WalletSubjectResolver.java  WalletAttributeMapper.java  WalletLinkService.java
      web/OpenId4VpVerifierController.java  web/WalletPageController.java  web/QrCodeSvg.java
  security/
    session/IdTokenSessionClaims.java            MODIFY  acr from session (Task 3)
    PageCspPolicy.java / SecurityConfig.java     MODIFY  wallet page CSP, /oid4vp/** exemptions
  service/key/RealmSigningKeys.java (+ SoftwareRealmSigningKeys)   NEW  (Task 5)
  service/federation/IdentityProviderConfigService.java          MODIFY secrets encrypt/redact (Task 4)
  common/startup/ProductionReadinessCheck.java                    MODIFY direct_post refusal
resources/
  templates/flow/wallet.html   static/js/wallet-poll.js   static/img/idp/eudi-wallet.svg
  templates/login.html          MODIFY wallet icon branch
  db/migration/V75__…  V76__…  schema.sql
helix-iam-server/src/test/java/io/helixiam/authorization/federation/wallet/…   (mirrors main)
helix-iam-server/src/test/java/io/helixiam/authorization/federation/wallet/testwallet/TestWallet.java
helix-iam-server/src/test/resources/wallet/vectors/…   (spec test vectors, with SOURCES.md)
helix-dashboard/src/…   providerCatalog.ts, ProviderWizard.tsx, ConnectionDetailPage.tsx, walletProvider.ts(+test)
helix-sandbox-rp/…  docs/eudi-wallet.md  docs/eudi-wallet-spec-notes.md
```

---

# Phase 0 — Prerequisites (one PR)

### Task 1: Pin the normative specifications and test vectors

**Why first:** spec §0 forbids copying field names from memory or drafts. Every later task reads its exact field names,
CBOR structures and handover formats from this note, not from this plan.

**Files:**
- Create: `docs/eudi-wallet-spec-notes.md`
- Create: `helix-iam-server/src/test/resources/wallet/vectors/SOURCES.md` and the vector files

- [ ] **Step 1:** Fetch the final texts and record, per spec, the version, date and URL:
  OpenID4VP 1.0 final; HAIP 1.0; RFC 9901 (SD-JWT) or latest draft; SD-JWT VC draft; `draft-ietf-oauth-status-list`
  (latest); ISO/IEC 18013-5 structures as profiled by OpenID4VP 1.0 Annex B; ARF PID Rulebook (Annex 3.1) version.
- [ ] **Step 2:** In `docs/eudi-wallet-spec-notes.md` write one section per spec quoting **verbatim** (with section
  numbers) at least:
  - OpenID4VP: request-object claims, `client_id` prefixes (`x509_san_dns`, `x509_hash`) and their exact syntax,
    `client_metadata` field names (JWKS, encryption enc values, `vp_formats_supported`), `response_mode` values,
    `direct_post` response (`redirect_uri`), `vp_token` shape (object keyed by DCQL id → **array**), `request_uri_method`,
    error codes, and the exact **OpenID4VPHandover / SessionTranscript** CDDL for the redirect/`direct_post` flows.
  - HAIP 1.0: required client-id prefix(es), required `alg`/`enc`, `request_uri_method`, whether `deviceMac` is
    allowed, recommended invocation scheme.
  - SD-JWT / SD-JWT VC: `typ` values, disclosure formats (object + array), `_sd`, `...`, `_sd_alg`, KB-JWT claims,
    exact `sd_hash` input.
  - Token Status List: claim structure, media type, `bits`, compression, `ttl`.
  - PID Rulebook: SD-JWT VC `vct` value(s), mdoc doctype + namespace, claim identifiers for both formats.
- [ ] **Step 3:** Copy official test vectors (SD-JWT examples, status-list examples, OpenID4VP examples, any 18013-5
  Annex D vectors available) into `src/test/resources/wallet/vectors/` and list each file's source URL and licence in
  `SOURCES.md`. Where no official vector exists, write "none — generated by TestWallet" for that item.
- [ ] **Step 4:** Commit: `git add docs/eudi-wallet-spec-notes.md helix-iam-server/src/test/resources/wallet && git commit -s -m 'docs(wallet): pin OpenID4VP 1.0, HAIP 1.0, SD-JWT, status list and PID rulebook references'`

**Every later task:** when a field name or structure in this plan disagrees with `docs/eudi-wallet-spec-notes.md`, the
notes win; record the deviation in the PR description.

---

### Task 2: Rotate the session id on every federated login (security)

**Files:**
- Modify: `helix-iam-server/src/main/java/io/helixiam/authorization/federation/FederatedLoginCompleter.java`
- Test: `helix-iam-server/src/test/java/io/helixiam/authorization/federation/FederatedLoginCompleterTest.java`
- Test: `helix-iam-server/src/test/java/io/helixiam/e2e/browser/FederatedSessionRotationBrowserE2eTest.java`

**Interfaces:** Produces: the session id changes exactly once on successful federated login, before the
SecurityContext is persisted.

- [ ] **Step 1: Write the failing unit test** (append to `FederatedLoginCompleterTest`):

```java
@Test
void completedFederatedLogin_rotatesTheSessionId_beforePersistingTheContext() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    final String before = request.getSession(true).getId();
    givenFlowCompletes();                       // existing helper in this test class
    completer.complete(USER_ID, request, new MockHttpServletResponse());
    assertThat(request.getSession(false).getId()).isNotEqualTo(before);
}
```

- [ ] **Step 2:** Run `mvn -B -q test -Dtest=FederatedLoginCompleterTest` → FAIL (same id).
- [ ] **Step 3:** In `complete(...)`, on the COMPLETED branch, call `request.changeSessionId()` immediately before
  `sessionEstablisher.persist(...)` (mirror `MagicLinkController.java:128`). Do **not** rotate on CHALLENGE (the MFA
  step rotates when it completes) — verify the MFA completion path already rotates; if not, add the same call there with
  its own test.
- [ ] **Step 4:** Browser test: sign in through the existing `FederatedLoginStubController`, read the session cookie
  before and after, assert it changed. Add the class to the pom execution `browser-on-queue-session-store`.
- [ ] **Step 5:** Run the federation tests + browser package → PASS. Commit
  `fix(security): rotate the session id on federated login`.

---

### Task 3: Brokered level of assurance reaches the ID token `acr`

**Files:**
- Modify: `federation/FederatedLoginCompleter.java`, `security/session/AuthTimeStamper.java`,
  `security/session/IdTokenSessionClaims.java`, `security/OAuthConfig.java:176` (call site),
  `security/SsoSessionBindingAuthorizationService.java` (bind `acr` like `sid`/`auth_time`)
- Modify: `federation/eid/EidScheme.java` (`EUDI_WALLET`), `federation/eid/EidLevelOfAssurance.java`
- Test: `security/session/IdTokenAcrClaimTest.java`, `e2e/FederatedAcrE2eTest.java`,
  `federation/eid/EidLevelOfAssuranceTest.java`

**Interfaces:**
- Consumes: `BrokeredIdentity.attributes().get("loa")` (eID already sets it).
- Produces: `public static final String ACR_SESSION_ATTRIBUTE = "HELIX_ACR"` on `AuthTimeStamper`;
  `SsoSessionBindingAuthorizationService.ACR_ATTRIBUTE = "helix_acr"`; ID token claim `acr` (and kept on refresh, like
  `auth_time`). `EidLevelOfAssurance.rung(EidScheme.EUDI_WALLET, uri)` == `rung(EidScheme.EIDAS, uri)`.

- [ ] **Step 1: Failing tests.** Unit: an authorization carrying `helix_acr=http://eidas.europa.eu/LoA/high` yields an
  ID token with that `acr`; absent attribute → no `acr` claim. `EidLevelOfAssuranceTest`:
  `rung(EUDI_WALLET, "http://eidas.europa.eu/LoA/high") == 3`. E2E: federated login via the stub with
  `loa=http://eidas.europa.eu/LoA/substantial` → code exchange → ID token `acr` equals it; a later refresh keeps it; a
  password login has no `acr`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement: `FederatedLoginCompleter` reads `loa` from the brokered identity (pass it in — add a
  `complete(String userId, String acr, HttpServletRequest, HttpServletResponse)` overload; keep the old signature
  delegating with `null`) and sets `HELIX_ACR` in the session after rotation; the code-binding step copies it to the
  authorization (same place `sid`/`auth_time` are bound); `IdTokenSessionClaims.apply` emits `acr` when present.
  Remove nothing from `ReservedClaims` (mappers still may not set `acr`).
- [ ] **Step 4:** Run → PASS (+ `OidcFlowSmokeE2eTest`, `IdTokenSessionClaimsE2eTest`). Commit
  `feat(oidc): brokered level of assurance is the ID token acr`.

---

### Task 4: Encrypt and redact identity-provider secrets (security)

**Files:**
- Modify: `service/federation/IdentityProviderConfigService.java`, `controller/admin/IdentityProviderAdminController.java`,
  realm export (`SecretMasking`)
- Create: `federation/ProviderSecretKeys.java` (which config keys are secret, per protocol)
- Create: `db/migration/V75__identity_provider_secrets.sql` + `schema.sql`
- Test: `e2e/IdentityProviderSecretsE2eTest.java`, `federation/ProviderSecretKeysTest.java`

**Interfaces:**
- Produces: `ProviderSecretKeys.isSecret(String protocol, String key)`; secret keys:
  oidc/social `clientSecret`; eid `spDecryptionPrivateKey`, `spSigningPrivateKey`; wallet
  `accessCertificatePrivateKey` (dev only) and `subjectPepper`. Secrets stored in a new column
  `identity_provider.secret_json` (`AttributeEncryption`), never in `config_json`; API returns `"<key>Set": true|false`
  instead of the value; `null`/absent on write keeps, `""` with `clear<Key>=true` clears (mirror the messaging-provider
  `clearSecret` contract).

- [ ] **Step 1: Failing e2e test:** create an OIDC IdP with `clientSecret`, then: GET returns no `clientSecret` value and
  `clientSecretSet=true`; raw `config_json` (JdbcTemplate) does not contain the secret; `secret_json` is not plaintext;
  export masks it; PUT without the key keeps it (login still works via the stub). Same for an eID IdP's private keys.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** V75: `ALTER TABLE identity_provider ADD COLUMN secret_json text;` then a Java migration or startup
  backfill moving existing secret keys out of `config_json` into the encrypted column (follow `LegacyBrandingBackfill`
  for the sql-init path). Service reads merge `secret_json` back into the runtime `Map<String,String>` so
  `FederationProviderFactory.fromStored` is unchanged.
- [ ] **Step 4:** Run → PASS (+ federation, eID, import/export tests, sql-init run). Mark **security** in CHANGES.
  Commit `fix(security): identity-provider secrets are encrypted at rest and never returned`.

---

### Task 5: `RealmSigningKeys` — a signing abstraction for the verifier access key

**Files:**
- Create: `service/key/RealmSigningKeys.java`, `service/key/SoftwareRealmSigningKeys.java`,
  `service/key/SigningKeyHandle.java`
- Create: `db/migration/V76__verifier_access_keys.sql` + `schema.sql`
- Test: `service/key/SoftwareRealmSigningKeysTest.java`

**Interfaces (Produces):**

```java
public interface SigningKeyHandle {
    String keyRef();                       // e.g. "software:acme/eudi-access-2026"
    com.nimbusds.jose.JWSAlgorithm algorithm();   // ES256 | ES384 | ES512
    java.util.List<java.security.cert.X509Certificate> certificateChain(); // leaf first, no root
    com.nimbusds.jose.JWSSigner signer();  // signs without exposing the private key to callers
}

public interface RealmSigningKeys {
    /** "software:<realm>/<name>" now; "pkcs11:" / "kms:" refs are rejected with a clear message (seam for later). */
    SigningKeyHandle resolve(String realmId, String keyRef);
    /** Admin upload of a key + chain (software store, DB-encrypted). Returns the keyRef. */
    String importKey(String realmId, String name, String privateKeyPem, String certificateChainPem);
}
```

- [ ] **Step 1: Failing tests:** import an EC P-256 key + chain → `resolve` signs a JWS that verifies with the leaf's
  public key; private key column is encrypted (not PEM in DB); key/cert mismatch → `IllegalArgumentException`
  ("private key does not match the certificate"); RSA 1024 refused; `pkcs11:` ref → "not supported yet"; resolving
  another realm's key → not found.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement (table `verifier_signing_key(realm_id, name, alg, private_key
  [AttributeEncryption], certificate_chain_pem, created_at, PK(realm_id,name))`). **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(keys): realm signing keys for verifier access certificates (software store, HSM seam)`.

---

# Phase 1 — Verification core (one PR, no HTTP)

### Task 6: Shared types, error codes, strict CBOR reader

**Files:**
- Create: `wallet/WalletErrorCode.java`, `wallet/WalletVerificationException.java`, `wallet/VerifiedPresentation.java`,
  `wallet/VerificationContext.java`, `wallet/PresentationVerifier.java`, `wallet/mdoc/StrictCbor.java`
- Modify: `helix-iam-server/pom.xml` — declare `com.nimbusds:nimbus-jose-jwt` **without a version** (Boot-managed) so
  the dependency is explicit; add to `VENDOR-MAP.md`.
- Test: `wallet/mdoc/StrictCborTest.java`, `wallet/WalletErrorCodeTest.java`

**Interfaces (Produces):**

```java
public enum WalletErrorCode {
    INVALID_RESPONSE, UNSUPPORTED_FORMAT, ISSUER_SIGNATURE_INVALID, ISSUER_UNTRUSTED, CREDENTIAL_EXPIRED,
    CREDENTIAL_NOT_YET_VALID, CREDENTIAL_REVOKED, CREDENTIAL_SUSPENDED, STATUS_UNAVAILABLE, STATUS_REQUIRED,
    HOLDER_BINDING_MISSING, HOLDER_BINDING_INVALID, NONCE_MISMATCH, AUDIENCE_MISMATCH, DISCLOSURE_INVALID,
    DIGEST_MISMATCH, DCQL_NOT_SATISFIED, VCT_NOT_ACCEPTED, DOCTYPE_NOT_ACCEPTED, ALGORITHM_NOT_ALLOWED,
    LIMIT_EXCEEDED, DECRYPTION_FAILED, STATE_MISMATCH, TRANSACTION_EXPIRED, REPLAY, WALLET_ACCESS_DENIED,
    WALLET_ERROR, SUBJECT_UNAVAILABLE, BROWSER_MISMATCH;
    /** Stable reason code for audit/UI, e.g. "wallet.credential_revoked". */
    public String reason() { return "wallet." + name().toLowerCase(java.util.Locale.ROOT); }
}

public final class WalletVerificationException extends RuntimeException {
    private final WalletErrorCode code;
    public WalletVerificationException(WalletErrorCode code, String safeDetail) { super(safeDetail); this.code = code; }
    public WalletErrorCode code() { return code; }
}

public record VerificationContext(String clientId, String nonce, String responseUri, byte[] encryptionJwkThumbprint,
        java.time.Instant now, java.time.Duration clockSkew, TrustAnchors anchors, StatusPolicy statusPolicy,
        java.util.Set<String> acceptedVcts, String acceptedDoctype, boolean allowLegacyVcSdJwtTyp) {}

public record VerifiedPresentation(String format,              // "dc+sd-jwt" | "mso_mdoc"
        java.util.Map<String, Object> claims,                   // normalised JSON-ish
        String issuerSubjectDn, String issuerSerialHex, String statusResult) {}

public interface PresentationVerifier {
    String format();
    VerifiedPresentation verify(String rawPresentation, VerificationContext context);
}
```

(`TrustAnchors` from Task 7, `StatusPolicy` from Task 10 — define both there; this task may use placeholders only if
the classes are created in the same PR before compile.)

- [ ] **Step 1: Failing tests for `StrictCbor`:** `decode(bytes, limits)` returns a Jackson `JsonNode`/CBOR tree for a
  valid DeviceResponse vector; depth 17 → `LIMIT_EXCEEDED`; > 10 000 items → `LIMIT_EXCEEDED`; > 256 KB →
  `LIMIT_EXCEEDED`; indefinite-length nesting bomb → `LIMIT_EXCEEDED`; tag 24 (embedded CBOR) is surfaced as bytes for
  a second bounded decode; tag 1004 (full-date) preserved.
- [ ] **Step 2:** FAIL. **Step 3:** Implement on `com.fasterxml.jackson.dataformat.cbor.CBORParser` with a token-level
  counter (depth, items, bytes) — never `readTree` without the counter. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(wallet): verification types, error codes and a bounded CBOR reader`.

---

### Task 7: `IssuerTrustValidator` (X.509 path validation)

**Files:** Create `wallet/trust/TrustAnchors.java`, `wallet/trust/IssuerTrustValidator.java`; Test
`wallet/trust/IssuerTrustValidatorTest.java` (+ a test CA builder `wallet/testwallet/TestPki.java` using BouncyCastle).

**Interfaces (Produces):**
```java
public record TrustAnchors(java.util.Set<java.security.cert.TrustAnchor> anchors,
        java.util.List<java.security.cert.X509Certificate> pinnedIntermediates, RevocationMode revocation) {
    public enum RevocationMode { OFF, SOFT_FAIL, HARD_FAIL }
    public static TrustAnchors fromPem(String pemBundle, String intermediatesPem, RevocationMode mode) { … }
}
public final class IssuerTrustValidator {
    /** Validates leaf-first chain (as in x5c / x5chain) to a configured anchor at {@code at}; returns the leaf. */
    public java.security.cert.X509Certificate validate(java.util.List<java.security.cert.X509Certificate> chain,
                                                        TrustAnchors anchors, java.time.Instant at);
}
```

- [ ] **Step 1: Failing tests:** chain to anchor → returns leaf; self-signed leaf not in anchors → `ISSUER_UNTRUSTED`;
  expired leaf → `CREDENTIAL_EXPIRED`… (use `ISSUER_UNTRUSTED` with detail "certificate expired" — record choice);
  leaf without `digitalSignature` key usage → `ISSUER_UNTRUSTED`; root included in `x5c` is tolerated (stripped);
  RSA 1024 leaf → `ALGORITHM_NOT_ALLOWED`; `HARD_FAIL` with unreachable CRL/OCSP → `ISSUER_UNTRUSTED`; `SOFT_FAIL`
  → passes and records a warning (assert via `LogCapture`, no PID data in it); `fromPem` with zero certs →
  `IllegalArgumentException`.
- [ ] **Step 2:** FAIL. **Step 3:** JDK `CertPathValidator("PKIX")`, `PKIXParameters` with `setDate(at)`,
  `PKIXRevocationChecker` options per mode (`SOFT_FAIL` → `Option.SOFT_FAIL`, OFF → `setRevocationEnabled(false)`).
  Key-usage per the profile recorded in Task 1 notes. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(wallet): issuer trust validation against configured anchors`.

---

### Task 8: SD-JWT parsing and disclosure processing

**Files:** Create `wallet/sdjwt/SdJwt.java`, `wallet/sdjwt/Disclosure.java`, `wallet/sdjwt/SdJwtDisclosures.java`;
Test `wallet/sdjwt/SdJwtDisclosuresTest.java` using the RFC/draft vectors from Task 1.

**Interfaces (Produces):**
```java
public record SdJwt(String issuerJwt, java.util.List<String> disclosures, String keyBindingJwt) {
    /** Splits "<iss-jwt>~<d1>~…~<kb-jwt>"; kb may be empty string → null. Enforces maxDisclosures and maxJwtBytes. */
    public static SdJwt parse(String presentation, int maxDisclosures, int maxJwtBytes);
    /** The exact ASCII string whose hash is sd_hash: everything up to and including the last '~' before the KB-JWT. */
    public String presentationWithoutKbJwt();
}
public final class SdJwtDisclosures {
    /** Resolves _sd / array "..." digests recursively; returns the fully disclosed claim object.
     *  Rejects: duplicate digests, unreferenced disclosures, disclosures overwriting plain claims, reserved names
     *  (_sd, ...), digests algorithm not in allow-list. */
    public static java.util.Map<String, Object> resolve(java.util.Map<String, Object> payload,
                                                        java.util.List<String> disclosures, String sdAlg);
    static String digest(String disclosureB64, String sdAlg);   // base64url(hash(ASCII(disclosure)))
}
```

Core digest implementation (must match the RFC — confirm against Task 1 notes):
```java
static String digest(final String disclosure, final String sdAlg) {
    final String jca = switch (sdAlg) {
        case "sha-256" -> "SHA-256";
        case "sha-384" -> "SHA-384";
        case "sha-512" -> "SHA-512";
        default -> throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "_sd_alg");
    };
    try {
        final byte[] h = java.security.MessageDigest.getInstance(jca)
                .digest(disclosure.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(h);
    } catch (java.security.NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
    }
}
```

- [ ] **Step 1: Failing tests:** RFC example resolves to the documented claims; array-element disclosure
  (`{"...": digest}`) resolved; recursive (nested object) disclosure resolved; duplicate digest → `DISCLOSURE_INVALID`;
  an extra disclosure not referenced → `DISCLOSURE_INVALID`; disclosure claim name equal to a plain claim →
  `DISCLOSURE_INVALID`; claim name `_sd` → `DISCLOSURE_INVALID`; 101 disclosures → `LIMIT_EXCEEDED`;
  `_sd_alg=md5` → `ALGORITHM_NOT_ALLOWED`; malformed base64 → `DISCLOSURE_INVALID`; `presentationWithoutKbJwt()`
  equals the vector's documented `sd_hash` input.
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS. **Step 5:** Commit
  `feat(wallet): SD-JWT parsing and selective-disclosure resolution`.

---

### Task 9: `SdJwtVcPresentationVerifier`

**Files:** Create `wallet/sdjwt/SdJwtVcPresentationVerifier.java`; Test `wallet/sdjwt/SdJwtVcPresentationVerifierTest.java`.
Extend `testwallet/TestWallet` with `sdJwtPid(Map claims, Instant iat, Instant exp, Optional<StatusRef>)` and
`present(SdJwtCredential, Set<String> disclose, String aud, String nonce)`.

**Interfaces:** Consumes Tasks 6–8, 10 (`TokenStatusListClient` injected; until Task 10 lands, inject an interface
`StatusEvaluator` defined here: `String evaluate(StatusReference ref, TrustAnchors anchors)` returning `"VALID"` or
throwing). Produces `format() = "dc+sd-jwt"`.

Order (fail closed, spec §7.3): parse → issuer JWT `typ` (`dc+sd-jwt`; `vc+sd-jwt` only if flag) → `alg` allow-list →
`x5c` chain via `IssuerTrustValidator` → JWS signature → `iss`, `vct ∈ acceptedVcts`, `iat/nbf/exp` with skew →
disclosures (Task 8) → KB-JWT required: `typ=kb+jwt`, signature with `cnf.jwk`, `aud == clientId`, `nonce`, `iat`
window, `sd_hash == base64url(SHA-256(presentationWithoutKbJwt))` → status (if `status.status_list` present; if absent
and `statusPolicy.required` → `STATUS_REQUIRED`) → output (claims + issuer DN + serial).

- [ ] **Step 1: Failing tests** — one positive (full PID, ES256) and one negative per check: tampered issuer
  signature; `alg=none`; `alg=HS256`; untrusted chain; `vct` not accepted; expired; `nbf` in future beyond skew;
  missing KB-JWT → `HOLDER_BINDING_MISSING`; KB signed by another key → `HOLDER_BINDING_INVALID`; wrong `aud` →
  `AUDIENCE_MISMATCH`; wrong `nonce` → `NONCE_MISMATCH`; KB `iat` stale (> window) → `HOLDER_BINDING_INVALID`;
  wrong `sd_hash` → `HOLDER_BINDING_INVALID`; `vc+sd-jwt` with flag off → `UNSUPPORTED_FORMAT`, with flag on → OK;
  status revoked → `CREDENTIAL_REVOKED`; status absent + required → `STATUS_REQUIRED`; ES384 positive.
- [ ] **Step 2:** FAIL. **Step 3:** Implement with Nimbus `SignedJWT`, `ECDSAVerifier`, `JWK.parse` for `cnf.jwk`.
  **Step 4:** PASS. **Step 5:** Commit `feat(wallet): SD-JWT VC presentation verification`.

---

### Task 10: `TokenStatusListClient`

**Files:** Create `wallet/status/StatusListToken.java`, `wallet/status/TokenStatusListClient.java`,
`wallet/status/StatusPolicy.java`, `wallet/status/StatusReference.java`; Test `wallet/status/TokenStatusListClientTest.java`
(local HTTPS stub server — reuse the Cloudflare-mock HTTPS pattern from the email tests).

**Interfaces (Produces):**
```java
public record StatusReference(int idx, String uri) {}
public record StatusPolicy(boolean required, OnUnavailable onUnavailable, java.time.Duration maxCache,
                           java.util.List<String> allowedHosts) {
    public enum OnUnavailable { FAIL_CLOSED, FAIL_OPEN_WITH_AUDIT }
}
public final class TokenStatusListClient implements StatusEvaluator {
    /** "VALID", or throws CREDENTIAL_REVOKED / CREDENTIAL_SUSPENDED / STATUS_UNAVAILABLE. */
    public String evaluate(StatusReference ref, TrustAnchors anchors);
}
```

Behaviour: `https` only; host resolved and checked with `OutboundUrlGuard.checkAllowed` (private/loopback/link-local
refused) **before** connecting; optional `allowedHosts` match; `Accept: application/statuslist+jwt`; body ≤ 1 MB;
JWT signature via `x5c` against the **same anchors**; `sub == uri`; `exp`/`ttl` freshness; `lst` base64url →
zlib inflate with ≤ 2 MB cap; `bits ∈ {1,2,4,8}`; status at `idx` (`0` VALID, `1` INVALID→REVOKED, `2`
SUSPENDED, other → REVOKED unless notes say otherwise); cache by `uri` for `min(ttl, maxCache)`; timeouts 3 s / 5 s.

- [ ] **Step 1: Failing tests:** valid index → VALID; revoked index → `CREDENTIAL_REVOKED`; suspended →
  `CREDENTIAL_SUSPENDED`; `bits=2` decoding; `sub` ≠ uri → `STATUS_UNAVAILABLE`; untrusted signer →
  `STATUS_UNAVAILABLE`; zip bomb (inflate > 2 MB) → `LIMIT_EXCEEDED`; `http://` → refused; **Review Focus 5**:
  `statusListUri_privateAddress_isRefusedWithoutConnecting` (stub server must record zero requests for
  `https://127.0.0.1:<port>/…` and `https://169.254.169.254/…`); host not in `allowedHosts` → refused; unreachable +
  `FAIL_CLOSED` → `STATUS_UNAVAILABLE`; unreachable + `FAIL_OPEN_WITH_AUDIT` → VALID with an audit/warn entry; cache
  hit makes no second request within ttl; timeout honoured (stub sleeps 6 s → STATUS_UNAVAILABLE within ~5 s).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS. **Step 5:** Commit
  `feat(wallet): token status list evaluation with SSRF guard and caching`.

---

### Task 11: COSE_Sign1 and the Mobile Security Object

**Files:** Create `wallet/mdoc/CoseSign1.java`, `wallet/mdoc/MobileSecurityObject.java`; Test `CoseSign1Test.java`,
`MobileSecurityObjectTest.java`. Extend `TestWallet` with `mdocPid(...)` (issues a DeviceResponse with IssuerAuth,
MSO, device key) — implemented with the same CBOR writer.

**Interfaces (Produces):**
```java
public record CoseSign1(byte[] protectedHeader, java.util.Map<Object,Object> unprotectedHeader, byte[] payload,
                        byte[] signature) {
    public static CoseSign1 decode(com.fasterxml.jackson.databind.JsonNode node);
    public int algorithm();                                         // COSE alg id (-7 ES256, -35 ES384, -36 ES512)
    public java.util.List<java.security.cert.X509Certificate> x5chain();   // label 33
    /** Verifies over Sig_structure ["Signature1", protected, external_aad(b""), payload] (RFC 9052 §4.4). */
    public boolean verify(java.security.PublicKey key, byte[] detachedPayloadOrNull);
}
public record MobileSecurityObject(String version, String digestAlgorithm, String docType,
        java.util.Map<String, java.util.Map<Integer, byte[]>> valueDigests, java.security.PublicKey deviceKey,
        java.time.Instant signed, java.time.Instant validFrom, java.time.Instant validUntil,
        StatusReference status) {
    public static MobileSecurityObject decode(byte[] taggedPayload);   // tag 24 wrapped, bounded via StrictCbor
}
```

Notes: ECDSA COSE signatures are raw `r||s`; convert to DER for JDK `Signature` (`SHA256withECDSA`) or use BC
`SHA256withPLAIN-ECDSA`. `deviceKey` is a COSE_Key (kty 2, crv 1/2/3, x, y) → `ECPublicKey`.

- [ ] **Step 1: Failing tests:** sign/verify round trip (ES256/ES384); tampered payload fails; alg not in allow-list
  (e.g. -257 RS256 or 0) → `ALGORITHM_NOT_ALLOWED`; missing x5chain → `ISSUER_UNTRUSTED`; MSO decode of the TestWallet
  PID gives docType/digestAlgorithm/validity; MSO with unknown digest alg → `ALGORITHM_NOT_ALLOWED`; COSE_Key with
  crv mismatch → `INVALID_RESPONSE`.
- [ ] **Step 2–4:** FAIL → implement → PASS. **Step 5:** Commit `feat(wallet): COSE_Sign1 and mdoc MSO decoding`.

---

### Task 12: `MdocPresentationVerifier`

**Files:** Create `wallet/mdoc/SessionTranscripts.java`, `wallet/mdoc/MdocPresentationVerifier.java`; Test
`MdocPresentationVerifierTest.java`, `SessionTranscriptsTest.java`.

**Interfaces:** `SessionTranscripts.openId4VpRedirect(String clientId, String nonce, byte[] jwkThumbprintOrNull,
String responseUri)` returns the CBOR-encoded SessionTranscript **exactly** per `docs/eudi-wallet-spec-notes.md`
(OpenID4VP 1.0 Annex B). `format() = "mso_mdoc"`.

Order (spec §7.4): base64url → `StrictCbor` → DeviceResponse; for each Document: `docType == acceptedDoctype`,
`status == 0` → IssuerAuth chain (`IssuerTrustValidator`) + signature → MSO `docType` matches, validity window
(`signed ≤ now`, `validFrom ≤ now+skew`, `now-skew ≤ validUntil`) → every IssuerSignedItem: digest of the tag-24 bytes
with `digestAlgorithm` equals `valueDigests[ns][digestID]` → DeviceAuth: build DeviceAuthentication
`["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]`, verify `deviceSignature` with MSO
`deviceKey`; `deviceMac` → `HOLDER_BINDING_INVALID` unless HAIP notes require support → MSO status (Task 10) → claims
`ns → {elementIdentifier → value}` (full-date → ISO-8601, bytes → base64url).

- [ ] **Step 1: Failing tests:** `SessionTranscriptsTest` against the spec example (from Task 1 vectors; if none,
  against a hex fixture computed by hand from the CDDL and checked in with its derivation in a comment); positive PID
  presentation; wrong docType → `DOCTYPE_NOT_ACCEPTED`; document `status != 0` → `INVALID_RESPONSE`; tampered
  IssuerSignedItem value → `DIGEST_MISMATCH`; item whose digestID is missing → `DIGEST_MISMATCH`; expired MSO →
  `CREDENTIAL_EXPIRED`; `signed` in the future → `INVALID_RESPONSE`; DeviceAuth over a transcript with another nonce →
  `NONCE_MISMATCH` (classify transcript mismatch as nonce/audience per notes); with another client_id →
  `AUDIENCE_MISMATCH`; missing DeviceAuth → `HOLDER_BINDING_MISSING`; deviceMac → `HOLDER_BINDING_INVALID`; untrusted
  IssuerAuth chain → `ISSUER_UNTRUSTED`; revoked via status → `CREDENTIAL_REVOKED`; CBOR depth bomb → `LIMIT_EXCEEDED`.
- [ ] **Step 2–4:** FAIL → implement → PASS. **Step 5:** Commit `feat(wallet): mdoc presentation verification over the OpenID4VP session transcript`.

---

### Task 13: `VpResponseDecryptor` (`direct_post.jwt`)

**Files:** Create `wallet/VpResponseDecryptor.java`; Test `VpResponseDecryptorTest.java`.

**Interfaces (Produces):**
```java
public record DecryptedResponse(com.fasterxml.jackson.databind.JsonNode vpToken, String state) {}
public final class VpResponseDecryptor {
    public DecryptedResponse decrypt(String compactJwe, com.nimbusds.jose.jwk.ECKey transactionKey,
                                     java.util.Set<com.nimbusds.jose.EncryptionMethod> allowedEnc);
}
```
Rules: header `alg == ECDH-ES` (only), `enc ∈ allowed`, `kid == transactionKey.getKeyID()`, size ≤ 256 KB; inner
payload has `vp_token` (object) and `state` (when sent).

- [ ] **Step 1: Failing tests:** round trip A128GCM and A256GCM; `alg=RSA-OAEP` → `ALGORITHM_NOT_ALLOWED`;
  `enc=A128CBC-HS256` → `ALGORITHM_NOT_ALLOWED`; wrong `kid` → `DECRYPTION_FAILED`; encrypted to another key →
  `DECRYPTION_FAILED`; nested `vp_token` that is a string not an object → `INVALID_RESPONSE`; 300 KB → `LIMIT_EXCEEDED`.
- [ ] **Step 2–4.** **Step 5:** Commit `feat(wallet): encrypted response decryption`.

---

### Task 14: DCQL builder and result matcher

**Files:** Create `wallet/dcql/DcqlQueryBuilder.java`, `wallet/dcql/DcqlResultMatcher.java`; Tests for both.

**Interfaces (Produces):**
```java
public final class DcqlQueryBuilder {
    /** PID preset: one credential query per enabled format, claims = requestedClaims mapped to each format's paths,
     *  credential_sets so either format satisfies. Returns the JSON object placed in the request's dcql_query. */
    public com.fasterxml.jackson.databind.node.ObjectNode pidQuery(WalletProviderConfig.Pid pid,
                                                                    java.util.List<String> formats);
}
public final class DcqlResultMatcher {
    /** vp_token must be an object keyed by query id → array of presentations. Verifies each with the format's
     *  verifier, checks the credential_sets are satisfied, and DROPS over-disclosed claims (logs names only). */
    public MatchedPresentations match(com.fasterxml.jackson.databind.JsonNode vpToken,
                                      com.fasterxml.jackson.databind.node.ObjectNode dcqlQuery,
                                      java.util.Map<String, PresentationVerifier> verifiers, VerificationContext ctx);
}
public record MatchedPresentations(java.util.List<VerifiedPresentation> presentations,
                                   java.util.Set<String> droppedClaimNames) {}
```

- [ ] **Step 1: Failing tests:** builder output equals a golden JSON (per notes field names) for both formats and for
  each single format; `vp_token` as a string or as `{id: "<single>"}` (not array) → `INVALID_RESPONSE`; only the mdoc
  query answered → satisfied via `credential_sets`; neither → `DCQL_NOT_SATISFIED`; an unknown query id in the
  response → `INVALID_RESPONSE`; **Review Focus 4** `overDisclosedClaims_areDroppedAndOnlyNamesLogged`
  (presentation discloses `resident_address`; result lacks it; `LogCapture` contains `resident_address` as a name only
  and never its value).
- [ ] **Step 2–4.** **Step 5:** Commit `feat(wallet): DCQL query building and response matching`. Then run the full
  suite + sql-init run; open the **Phase 1 PR**.

---

# Phase 2 — Login flow end to end (one PR)

### Task 15: `WalletProviderConfig`, validation, properties and stored config

**Files:** Create `wallet/WalletProviderConfig.java`, `wallet/WalletConfigValidator.java`; Modify
`FederationProviderProperties.java` (`private List<WalletProviderConfig> wallet = new ArrayList<>();` + null-guarded
setter, mirroring `eid`); Test `WalletConfigValidatorTest.java`, `WalletProviderConfigStoredTest.java`.

Record mirrors spec §9 exactly (nested records `Pid`, `StatusList`, `Subject`), plus `accessKeyRef` (Task 5 keyRef)
instead of a raw key; `accessCertificatePrivateKey` accepted **only in the dev profile** (stored as a secret, Task 4).
`WalletProviderConfig.fromStored(Map<String,String>)`: lists as JSON arrays in the flat map (`credentialFormats`,
`pid.sdJwtVcts`, `pid.requestedClaims`, `statusList.allowedHosts`), PEM bundles as plain strings, enums
case-insensitive.

Validator errors (field → message): SAN of leaf ≠ `clientIdHost` (for `x509_san_dns`); key ≠ certificate; zero trust
anchors; zero formats; unknown format; `responseMode=direct_post` outside dev; TTL outside 60–900;
`subject.strategy=ATTRIBUTE_TUPLE` without `acknowledgeWeakSubject`; `minimumLoa` not an eIDAS URI.

- [ ] Steps: failing tests for each validator rule and for YAML + stored round-trips → implement → PASS → commit
  `feat(wallet): provider configuration and validation`.

### Task 16: Transaction model and stores (in-memory + Redis)

**Files:** Create `transaction/WalletTransaction.java`, `WalletTransactionStore.java`, `InMemoryWalletTransactionStore.java`,
`RedisWalletTransactionStore.java`; wire in `FederationConfig` (Redis when `helix.iam.session-store=redis` or
`helix.iam.token-store=redis`, else in-memory with a startup WARN when more than one replica is configured);
Tests `InMemoryWalletTransactionStoreTest`, `RedisWalletTransactionStoreTest` (Testcontainers Redis, as in the e2e base).

**Interfaces (Produces):**
```java
public enum Flow { SAME_DEVICE, CROSS_DEVICE }
public enum Status { CREATED, REQUEST_FETCHED, RESPONSE_RECEIVED, VERIFIED, FAILED, EXPIRED, REDEEMED }
public record WalletTransaction(String transactionId, String sameDeviceRequestId, String crossDeviceRequestId,
        String responseId, String realmId, String providerAlias, String helixState, String browserBindingHash,
        String nonce, String encryptionJwkJson /* private, encrypted at rest in Redis */, String dcqlQueryJson,
        Flow flow, Status status, String responseCode, String verifiedIdentityJson, WalletErrorCode failureCode,
        java.time.Instant createdAt, java.time.Instant expiresAt) {}
public interface WalletTransactionStore {
    void create(WalletTransaction tx);
    java.util.Optional<WalletTransaction> byTransactionId(String id);
    /** Atomic CREATED→REQUEST_FETCHED, records which requestId (flow) was used. Empty if not CREATED / expired. */
    java.util.Optional<WalletTransaction> claimRequest(String requestId);
    /** Atomic REQUEST_FETCHED→RESPONSE_RECEIVED for responseId. Empty on second call. */
    java.util.Optional<WalletTransaction> claimResponse(String responseId);
    void complete(String transactionId, String responseCode, String verifiedIdentityJson);   // → VERIFIED
    void fail(String transactionId, WalletErrorCode code);                                     // → FAILED
    /** Atomic VERIFIED→REDEEMED iff responseCode, helixState and browserBindingHash all match. */
    java.util.Optional<WalletTransaction> redeem(String responseCode, String helixState, String browserBindingHash);
}
```
Flow mechanism (spec §6, documented): **two request ids per transaction** — the QR carries `crossDeviceRequestId`,
the same-device button carries `sameDeviceRequestId`; `claimRequest` sets `flow` from which id was fetched;
`redirect_uri` is returned from `direct_post` only when `flow == SAME_DEVICE`.

Redis: one hash per transaction (`helix:wallet:tx:{id}`) + index keys (`req:`, `resp:`, `code:`) with TTL =
`expiresAt`; every transition a Lua script (compare `status` then set). Private JWK encrypted with `AttributeEncryption`.
Never store `vp_token`; `verifiedIdentityJson` = mapped `BrokeredIdentity` + audit summary only.

- [ ] **Step 1: Failing tests** (same suite runs against both stores via an abstract test): create/lookup; second
  `claimRequest` empty; second `claimResponse` empty; **Review Focus 2** 20 threads × `claimResponse` → exactly one
  non-empty; `redeem` with wrong state/binding → empty and still VERIFIED; second `redeem` empty; expired → every
  operation empty; Redis keys expire (TTL set); `encryptionJwkJson` not plaintext in Redis.
- [ ] Steps 2–5 → commit `feat(wallet): atomic transaction store (in-memory and Redis)`.

### Task 17: `AuthorizationRequestFactory` (signed request object) + `TestWallet` request parsing

**Files:** Create `wallet/AuthorizationRequestFactory.java`; extend `testwallet/TestWallet` (`fetchAndVerifyRequest`,
`respond`); Tests `AuthorizationRequestFactoryTest.java`.

Produces: `String signedRequestObject(WalletTransaction tx, WalletProviderConfig cfg, SigningKeyHandle key, String
requestUriBase)`; `String invocationUrl(WalletTransaction tx, WalletProviderConfig cfg, Flow flow)`;
`String clientId(WalletProviderConfig cfg)` (`x509_san_dns:<host>` or `x509_hash:<b64url sha256 DER leaf>` per notes).
Header `typ=oauth-authz-req+jwt`, `alg` from key, `x5c` leaf-first without root. Claims per notes: `response_type`,
`client_id`, `response_mode`, `response_uri`, `nonce`, `state`, `dcql_query`, `client_metadata` (`jwks` with the
transaction **public** enc key `use=enc`, `alg=ECDH-ES`, `kid`; supported enc values; `vp_formats_supported`), `aud`,
`iat`, `exp` (= tx expiry).

- [ ] Failing tests: TestWallet verifies the JWS with the `x5c` leaf and checks `client_id` binding (SAN / hash);
  `exp` ≤ transaction expiry; no private JWK members in `client_metadata.jwks`; invocation URL uses the configured
  scheme and percent-encodes `request_uri`; `x509_hash` value equals the expected digest → implement → PASS → commit
  `feat(wallet): signed OpenID4VP request objects`.

### Task 18: Endpoints — request, response, wallet page, status, callback redemption

**Files:** Create `web/OpenId4VpVerifierController.java`, `web/WalletPageController.java`, `web/QrCodeSvg.java`,
`templates/flow/wallet.html`, `static/js/wallet-poll.js`, `static/img/idp/eudi-wallet.svg`; Modify `SecurityConfig.java`
(permitAll + CSRF-exempt `/oid4vp/**`; dedicated rate limit + 256 KB body limit; `/broker/*/wallet/**` uses the login
CSP), `PageCspPolicy.java` (wallet page: `img-src 'self' data:` for the SVG QR, `connect-src 'self'`), `login.html`
(icon branch for `eudi-wallet`); Tests `e2e/WalletFlowE2eTest.java`, `e2e/browser/WalletLoginBrowserE2eTest.java`.

Routes (all under `/realms/{realm}`; `RealmRoutingFilter` strips the prefix):
- `GET /broker/{alias}/wallet?tx=` → page with server-side SVG QR (ZXing → SVG, no CDN) of the **cross-device**
  invocation URL and an "Open wallet" link with the **same-device** URL; themed via `fragments/theme`.
- `GET /broker/{alias}/wallet/status?tx=` → `{status, next?}`; only if `sha256(session id salt)` equals
  `browserBindingHash`, else 404. `next` = `/broker/{alias}/callback?response_code=…&state=…` when VERIFIED.
- `GET|POST /oid4vp/{alias}/request/{requestId}` → `application/oauth-authz-req+jwt`, single use (`claimRequest`).
- `POST /oid4vp/{alias}/response/{responseId}` → form `response` (JWE) or `vp_token`+`state` (dev `direct_post`) or
  `error`; `claimResponse` → decrypt → state check → `DcqlResultMatcher` → subject + mapping (Tasks 20–21) →
  `complete` or `fail`; returns `200 {"redirect_uri": …}` only for SAME_DEVICE, else `200 {}`; errors use spec error
  codes only, never internal detail.
- Realm check on every endpoint: `tx.realmId == RealmContextHolder.get()` else 404.

- [ ] **Step 1: Failing e2e tests** (TestWallet drives HTTP): cross-device success (status flips to COMPLETED within
  one poll; browser follows `next`; logged in); same-device success (direct_post returns `redirect_uri`, browser lands on
  callback); cross-device `direct_post` returns `{}` (no redirect); request fetched twice → second 404; response posted
  twice → second rejected (REPLAY); wallet `error=access_denied` → status FAILED, page shows retry; expired transaction
  → EXPIRED; **Review Focus 1** `statusAndCallback_fromAnotherBrowserSession_areRefused`; endpoint for realm A tx
  called under realm B → 404; 300 KB body → 413; no CSRF token needed on `/oid4vp/**`, still required elsewhere.
- [ ] **Step 2: Browser test** (Playwright): the wallet page renders, has no inline style/script, CSP has no
  `unsafe-inline`, QR `<img>`/inline SVG present, polling JS completes the login when TestWallet posts.
- [ ] Steps 3–5: implement → PASS (add the browser class to the queue-store pom execution) → commit
  `feat(wallet): verifier endpoints, wallet page and browser binding`.

### Task 19: `WalletIdentityProvider` and factory wiring

**Files:** Create `wallet/WalletIdentityProvider.java`; Modify `spi/IdpMetadata.java` (`Protocol.WALLET` — additive),
`FederationProviderFactory.java` (`build` iterates `properties.getWallet()`; `fromStored` `case "eudi-wallet",
"openid4vp", "wallet"`; `inferIconKey` → `"eudi-wallet"`; constructor gains the wallet collaborators); Tests
`WalletIdentityProviderTest.java`, `FederationProviderFactoryTest` (new cases).

`start(ctx)`: create transaction (nonce, ephemeral P-256 enc key with `kid`, two request ids, responseId, helixState =
`ctx.state()`, browser binding passed via `ctx` — **SPI note:** `AuthnRequestContext` has no session access; add a
backward-compatible field via a new 4-arg constructor `AuthnRequestContext(realmId, state, callbackUri,
browserBindingHash)` keeping the 3-arg one; the controller computes the hash) → `RedirectResponse` to
`/realms/{realm}/broker/{alias}/wallet?tx=…`.
`callback(ctx)`: `redeem(response_code, ctx.expectedState(), bindingHash)` → `BrokeredIdentity` from stored JSON; any
failure → exception the controller maps to the existing `?error=federation` path with a wallet reason.
`logout`: no-op.

- [ ] Failing tests: factory builds from YAML and stored config (all three protocol aliases); metadata protocol
  `WALLET`, icon `eudi-wallet`; `start` returns the wallet-page redirect and persists a CREATED transaction; `callback`
  with wrong state → failure; with right state + binding → identity; reused code → failure → implement → PASS →
  commit `feat(wallet): wallet identity provider and factory wiring`.

### Task 20: Attribute mapping and level of assurance

**Files:** Create `wallet/WalletAttributeMapper.java`; Modify `EidLevelOfAssurance` usage; Test
`WalletAttributeMapperTest.java`.

Mapping from the PID Rulebook names recorded in Task 1 (record the ARF version in a code comment): SD-JWT and mdoc
names → `given_name`, `family_name`, `birthdate`, `nationalities`, optional `place_of_birth`, `address.*`,
`issuing_country`, `issuing_authority`, `age_over_18`; plus `helix_wallet_format`, `helix_wallet_issuer` (issuer DN);
`loa` = `http://eidas.europa.eu/LoA/high` when the issuer chain validated to a configured PID-provider anchor; enforce
`minimumLoa` via `EidLevelOfAssurance.meetsMinimum(EUDI_WALLET, …)`. Admin overrides go through the existing
`AttributeMapperRules` (stored `mappers` JSON) — no parallel mechanism. `email=null`, `emailVerified=false`.

- [ ] Failing tests: SD-JWT and mdoc PIDs map to identical attributes; dates normalised; unknown extra claims not mapped;
  `minimumLoa` above high impossible → refused; admin mapper rule renames a claim → implement → PASS → commit
  `feat(wallet): PID attribute mapping and eIDAS level of assurance`.

### Task 21: Subject resolution, pepper and wallet linking

**Files:** Create `wallet/WalletSubjectResolver.java`, `wallet/WalletLinkService.java`; Modify account console
(`templates/account/index.html` "Link EU Digital Identity Wallet" action, `AccountConsoleController`), V77 migration
(`realm_wallet_pepper` or reuse realm secrets — follow how realm secrets are stored, encrypted) + `schema.sql`; Tests
`WalletSubjectResolverTest.java`, `e2e/browser/WalletLinkBrowserE2eTest.java`.

Rules (maintainer decision 1):
- `ADMINISTRATIVE_NUMBER`: `externalSubject = HMAC-SHA256(realmPepper, issuing_country + ":" + personal_administrative_number)`
  hex. Missing number → **not** a failure; go to the link path.
- No number: compute `tupleSubject = HMAC(pepper, normalise(issuing_country, family_name, given_name, birthdate,
  place_of_birth?))` (NFC, trim, lower-case, single spaces). Existing link for `tupleSubject` → sign in. No link →
  show "Link your wallet": the user signs in with an existing method, then completes the wallet link in the account
  console (wallet flow started with `purpose=link`, requires `acknowledgeWeakSubject=true` on the provider; otherwise
  `SUBJECT_UNAVAILABLE`). The tuple is **never** used to create an account or to auto-link by name.
- Never auto-link by email/name; JIT creation only with an administrative number.

- [ ] Failing tests: **Review Focus 3** `sameNumberDifferentCountry_givesDifferentSubjects`; different pepper →
  different subject; number present → JIT creates account (when policy allows); number absent, no link →
  `SUBJECT_UNAVAILABLE` + link page; number absent, flag off → link refused with explanation; link flow in the browser
  (sign in with password → account console → link → later wallet-only sign-in lands on that account); a second person
  with a different tuple cannot use the link → implement → PASS → commit
  `feat(wallet): pepper-hashed subjects and explicit wallet linking`.

### Task 22: Audit, logging hygiene, readiness check

**Files:** Modify the controller/provider to emit `WALLET_LOGIN_SUCCESS`, `WALLET_LOGIN_FAILURE`,
`WALLET_STATUS_CHECK_FAILED` via `AuditLog.emit(AuditEvent.authn(...))` with detail `{transactionId, alias, format,
issuerDn, result, reason}`; `ProductionReadinessCheck` (`direct_post` provider outside dev → fatal); Tests
`WalletAuditE2eTest`, `ProductionReadinessCheckTest` (new case), `WalletLogHygieneE2eTest`.

- [ ] Failing tests: every rejection in spec §15 yields a distinct `WalletErrorCode` + FAILURE audit event; happy path
  with `LogCapture.all()` contains none of: the PID values, nonce, `response_code`, `vp_token` fragments, JWK `d`;
  readiness check fatal on a `direct_post` provider outside dev → implement → PASS → commit
  `feat(wallet): audit events, log hygiene test and production readiness check`.

### Task 23: Acceptance matrix (spec §15) and Phase 2 verification

**Files:** `e2e/WalletAcceptanceE2eTest.java` (one test per §15 rejection row, both formats where applicable).

- [ ] Write the matrix; run; fix gaps. Run full suite, sql-init run, browser package on both session stores, the k3d
  release gate (`e2e/monthfold/k3d-helm.sh`). Triage any CodeQL findings into `CODEQL-TRIAGE.md`. Open the
  **Phase 2 PR** (description: library decisions, spec versions with dates, every conflict listed above, open questions).

---

# Phase 3 — Admin, sandbox and docs (one PR)

### Task 24: Console — "EUDI Wallet (OpenID4VP)" provider

**Files (helix-dashboard):** `src/components/providerCatalog.ts` (new family `"wallet"`, type entry with neutral icon),
`ProviderWizard.tsx`, `src/pages/ConnectionDetailPage.tsx` (`familyOf` → `"wallet"`, tabs, required fields),
`src/pages/walletProvider.ts` + `walletProvider.test.ts` (pure model + validation mirroring `WalletConfigValidator`),
Storybook story, en/nl strings.

Form: access key (import key + chain → keyRef via a new `POST /admin/realms/{r}/verifier-keys`, or pick an existing
ref), client-id scheme + host (shows SAN check result), trust anchors upload with a parsed preview (subject, issuer,
expiry), PID claim picker (warning > 5 claims, warning if `personal_administrative_number` requested without the
`ADMINISTRATIVE_NUMBER` strategy), formats, subject strategy with inline explanation and the weak-tuple warning,
status-list options, response mode (direct_post disabled outside dev), TTL. Secrets write-only (Set/Replace/Remove).

- [ ] TDD the pure validator (vitest); build the form with the design-system kit (zero inline styles, full width);
  `npm test`, `npm run build`; screenshots 1440/390 light/dark; **independent UI/UX review agent** sign-off → commit
  `feat(console): EUDI Wallet provider configuration`.

### Task 25: Sandbox RP demo

**Files:** `helix-sandbox-rp/README.md` (walkthrough), demo realm seed (`e2e`-style script) using the TestWallet as a
small runnable CLI (`mvn -q exec:java` in test scope or a `helix-test-wallet` jar) — **test-only, never in the server
image**.

- [ ] Script creates realm + wallet provider + test CA anchors; README walks cross-device and same-device; verify by
  running it once → commit `docs(sandbox): EUDI Wallet demo with the test wallet`.

### Task 26: Documentation and claims

**Files:** `docs/eudi-wallet.md` (operator guide: RP registration with the national registrar, access certificate,
trust anchors are manual until trusted-list support, subject strategy and the linking model, data minimisation,
limitations, status list behaviour, "bring your own registration" wording), `docs/FEATURES.md` row
"EUDI Wallet (OpenID4VP verifier) | Experimental | `authorization/federation/wallet` | <test count>",
`ROADMAP.md`, `CHANGELOG.md`/`CHANGES-1.0.md`, `helix-iam-server/VENDOR-MAP.md` (Nimbus now explicit; ZXing core use),
`helix-iam-server/ADAPTERS.md`, `helix-iam-server/SECURITY-REVIEW.md` (threat model: QR relay, replay, browser binding,
SSRF via status lists, weak-tuple linking residual risk), `helix-iam-server/DEFERRED-SECURITY-WORK.md` (trusted-list
automation, OCSP hard-fail default, HSM/KMS key providers, deviceMac).
GDPR: verify export/delete cover wallet-derived attributes and the wallet link; add tests (`WalletGdprE2eTest`).

- [ ] Write, verify every curl/path against the controllers, run the full suite once more → commit
  `docs(wallet): operator guide, feature matrix, security review` → open the **Phase 3 PR**.

---

# Phase 4 — Interop and stretch (separate plan)

Write `docs/superpowers/plans/<date>-eudi-wallet-phase4.md` after Phase 3 merges: OpenID Foundation conformance suite
(OpenID4VP 1.0 + HAIP 1.0 verifier) with a recorded pass/deviation list; EU reference wallet + one national test
wallet; W3C Digital Credentials API (`dc_api`/`dc_api.jwt`); `EuTrustedListSource` (ETSI TS 119 612); Terraform
resource. The step-up / verify-only flow (`NONE` strategy) gets its own plan as well (maintainer decision 4).
