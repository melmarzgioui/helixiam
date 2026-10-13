# Final whole-branch review: EUDI Wallet (OpenID4VP 1.0 / HAIP 1.0 verifier)

- Branch: `feature/eudi-wallet` (worktree `<local>`)
- Range: `0a867c3..c86cfb8`. 53 commits, 314 files, about 45k lines.
- What was implemented: the EUDI wallet verifier, its login flow, account linking, the admin console, the demo and the docs.
- Plan: `docs/superpowers/plans/2026-10-09-eudi-wallet-openid4vp.md`
- Spec: `docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md`
- Reviewer stance: read-only. I made no code changes. I simulated the security-branch merge with
  `git merge-tree --write-tree feature/eudi-wallet fix/pre-1.0-security`, which writes objects only and
  does not touch any worktree.

I worked in passes rather than reading all 45k lines:

1. The ledger, the plan, the spec, the threat model, DEFERRED-SECURITY-WORK and the per-task reviews.
2. An end-to-end trace of the login path through the main source.
3. The seams between tasks: registry, store refresh, completers, rate limit, audit.
4. The docs against the code.
5. The merge simulation against `fix/pre-1.0-security`.

I did not re-review the cryptographic verifiers line by line. Tasks 6–14 had adversarial per-task reviews,
and their accepted residuals are listed in DEFERRED-SECURITY-WORK.md. I ran no tests. Every claim below
comes from reading code. Where a finding needs runtime confirmation, it says so.

---

## Verdict: **Ready after fixes**

The verifier core, the transaction model and the login/link seams are sound. They fail closed, the realm
checks are consistent, and log hygiene is good. Three issues on the branch should be fixed before it
merges. All three sit at seams between tasks, not inside a task:

- **F1.** The admin-console/stored path works for exactly one realm at a time.
- **F2.** A wallet login that goes through a step-up is never audited.
- **F3.** Likely: a percent-encoded path bypasses the wallet rate limits and the body limit.

Separately, merging `fix/pre-1.0-security` has one **silent semantic break**: every wallet login is refused
after the merge. It also has three behaviour overlaps that need deliberate resolution. See §5.

---

## 1. Strengths

- **One construction point per seam.** `VerificationContext` is built only in
  `WalletIdentityProvider.verificationContext` (WalletIdentityProvider.java:381-386). The one `StatusPolicy`
  instance goes both into the context and into the `TokenStatusListClient` the verifiers use
  (WalletIdentityProviders.java:113-128). Nothing builds a second context with different nonce, client_id or
  response_uri inputs. `client_id` comes from the same `AuthorizationRequestFactory.clientId(config, key)` for
  the request object and for verification. So does `response_uri`, from the same `idp.base.url`.
- **Transactions are never left stuck.** Every failure after a claim fails the transaction:
  - the request object, including key/KMS errors: OpenId4VpVerifierController.java:103-116;
  - the response, for `WalletVerificationException` and any `RuntimeException`: WalletResponseHandler.java:148-170;
  - a wrong-realm or wrong-provider claim: :137-147.

  The only accepted window is the `issueResponseCode` crash window (ruling, self-expires ≤ 900 s).
- **Realm checks are uniform.** These all re-check realm and provider and answer a bare 404 or
  `error=federation`, matching spec conflict 6:
  - `WalletEndpoints.provider` and `ownedHere` (request, response, page, status);
  - `redeemTransaction` (WalletIdentityProvider.java:268-271);
  - `start()` keyRealm (:171-173);
  - `AccountWallets.provider` (link).
- **Secrets stay out of logs, audit and exceptions.**
  - Exception messages carry field names and limits only; the grep shows no values concatenated in.
  - JSON parse errors are swallowed into fixed messages (`VerifiedIdentityJson.parse`), so Jackson source
    snippets cannot leak PID.
  - `helixState` never reaches the wallet; the wallet state is `SHA-256(txId)`.
  - Codes and request ids are stored hash-only in Redis.
  - The subject HMAC was taken out of the logs (T22).
- **The account decision is pure and committed late.** `WalletLinkService.decide` is pure. The upgrade link is
  committed only after the whole login succeeded. A throwing or refusing commit undoes the session in both
  completion paths. This is a careful piece of design.
- **Status fail-open is narrowly scoped.** Integrity failures and policy refusals always fail closed. Only
  transient availability failures may fail open, and only with an audit entry.
- **The §6.5 appended-anchor bypass was caught and fixed on the PKIX-validated path** (T19), with an adversarial
  re-review.
- **Several fixes help every connector, not only the wallet:**
  - federated session-id rotation (T2);
  - typed LoA → `acr`, so a free-form `loa` attribute can no longer be forged into acr (T3);
  - IdP secrets encrypted and redacted (T4);
  - the Nimbus CVE-2025-53864 bump.

---

## 2. End-to-end trace (SD-JWT and mdoc; same-device and cross-device)

| Step | Code | Same-device / cross-device | Notes |
|---|---|---|---|
| start | `FederationBrokerController.start` → `BrowserBinding.begin` → `WalletIdentityProvider.start` | Shared | Discards the previous tx of this browser and alias. The keyRealm check raises a federation error. A full store answers `/wallet/unavailable` (503). |
| tx | `WalletTransaction` CREATED: 4×256-bit ids, 128-bit nonce, ephemeral P-256 ECDH-ES key, DCQL query, binding hash, TTL | Two request ids, one per flow | The DCQL query is frozen into the tx at start, so a later config edit does not change an in-flight tx. |
| page | `WalletPageController.page` | QR (cross-device URL) plus "Open wallet" (same-device URL) | Bound by binding hash plus realm/alias. EXPIRED reads as unknown. |
| request object | `claimRequest(requestId)` (records the flow) → `signedRequestObject` | Single fetch | GET and POST (`wallet_nonce` echoed). |
| response | `claimResponse` → decrypt (enc set constant) → state == walletState → `DcqlResultMatcher` (verifiers by format, the one context) → `WalletAttributeMapper` (minimumLoa) → `WalletSubjectResolver` → `decide` (pure) → `complete(code?)` | Same-device: code returned in `redirect_uri`. Cross-device: no code; `issueResponseCode` on the bound browser's poll. | mdoc: SessionTranscript uses the JWK thumbprint of the tx key (encrypted mode only), the client_id, the nonce and the response_uri. |
| callback | `redeemTransaction` (code + session state + binding, single use) → `WalletLoginCompleter` | Shared | Existing → `FederatedLoginCompleter.complete(user, acr, pendingCommit)`. Provision → JIT plus insert-if-absent link, and the race loser is deleted. Refused → link page. |
| session | `changeSessionId` → persist → commit-or-undo → `stamp` (clears stale acr) → acr attribute → `SsoSessionBindingAuthorizationService` binds acr into the code → ID token `acr` | Shared | **F2:** if the post-broker flow CHALLENGEs, success is never audited. |

**Error-code consistency.** Codes are consistent within each layer.

- At the callback, a reused `response_code` and a redeem from another browser session both surface as
  `STATE_MISMATCH`. The outer broker state check fires first (WalletAcceptanceE2eTest:425-475 pins and
  explains this).
- For mdoc, a wrong nonce and a wrong aud both map to `HOLDER_BINDING_INVALID` (T12 ruling: a detached
  transcript signature cannot tell them apart).

Both are defensible, but both are **deviations from §15 "a distinct `WalletErrorCode`" for each listed
rejection**. They must be listed in the PR description's deviation list. Today they are documented only in
test javadoc.

---

## 3. Issues

### Critical (must fix)

None on the branch itself. One merge-time break is in §5 (M1).

### Important (fix before merge)

**F1. The stored/console wallet provider works for one realm at a time, and the documented workaround makes it worse.**

The code paths involved:
- `FederationStoreRefresher.refresh(realm)` (FederationStoreRefresher.java:46) calls
  `registry.reload(providers)`.
- `IdentityProviderRegistry.reload` (IdentityProviderRegistry.java:50) **replaces the whole dynamic map** with
  that one realm's providers.
- Startup loads only `helix.federation.store.realm`, which defaults to `master`
  (FederationConfig.java:129-134).
- The dynamic map is keyed by alias only.

The consequences, all from reading the code:

1. **After a restart, a wallet connection in any non-master realm is inert.** The wallet's design binds a
   stored provider, its key and its pepper to its own realm. So "a wallet in a tenant realm" is the normal
   case, not an edge case.
2. **Saving any IdP in realm B unloads every store-backed provider of realm A, master included.** That is the
   effect of the reload above, and the admin write triggers it at IdentityProviderAdminController.java:127-138.
   `docs/eudi-wallet.md:69-76` advises exactly that: "re-save the connection after every restart". The
   workaround swaps which realm is broken.
3. **The console wizard defaults every realm's wallet alias to `eudi-wallet`** (ProviderWizard.tsx:125). Two
   realms that keep the default collide in the alias-keyed registry. Only one survives, and the other realm's
   button starts a login that `start()` refuses with "belongs to another realm".
4. **The login page lists every registry entry unfiltered** (LoginController.java:200-208). Every realm's login
   page shows wallet buttons of other realms, and those buttons always fail.
5. With the default `helix.federation.store.enabled=false`, no console-created wallet works at all. The Helm
   chart does not set the flag. Documented, but it is a sharp default.

Severity for this feature: **Important**. Spec §15's first criterion, "configure via the stored-config path,
and it appears on the login page", holds only for a single-realm deployment with the flag on. Security is
not affected: every path fails closed. Availability for multi-realm deployments is broken, and the docs
steer operators into making it worse.

Minimum fix:
- (a) Make `refresh` reload **all** realms. Run it at startup and after each write. The simplest version is to
  iterate the realm list and do one `reload` of the union.
- (b) Refuse, at admin write, a wallet alias that a stored provider in another realm already uses. Or key the
  dynamic map by (realm, alias). Make the wizard default realm-unique.
- (c) Filter wallet metadata on the login page with `servesRealm(currentRealm)`.
- (d) Fix `docs/eudi-wallet.md` §2.2 and DEFERRED-SECURITY-WORK accordingly.

Turning the flag on by default, or showing a console banner when it is off, is optional and the
maintainer's call.

**F2. A wallet login that passes a post-broker step-up is never audited.** Spec §10.8 requires
`WALLET_LOGIN_SUCCESS` / `FAILURE`.

- `WalletLoginCompleter.completeLogin` emits nothing for `STEP_UP_VIEW` (WalletLoginCompleter.java:174-195).
  Its javadoc says "`completeLogin` will audit it when the step-up itself resolves".
- Nothing does that. `FlowController.submitChallenge` COMPLETED (FlowController.java:120-141) commits the
  pending link and promotes acr, but emits no wallet event.
- An abandoned step-up is never audited either.

Today this hits realms whose post-broker flow challenges for other reasons, such as risk-based or conditional
steps. After `fix/pre-1.0-security` merges (`MfaEnabledCondition` now evaluates the brokered user), it hits
**every MFA-enabled user**. Fix: carry a small "wallet login" audit marker (alias, txId, format, issuer DN) on
`FlowExecutionState`, like `pendingCommit`, and emit success in `FlowController` COMPLETED. Add an e2e test
with an MFA-enabled user.

**F3. Likely: a percent-encoded path bypasses the wallet's rate limits and body limit. Confirm with a failing
test first.**

- `RealmRoutingFilter` sets `servletPath` to the **raw, still-encoded** remainder of `getRequestURI()`
  (RealmRoutingFilter.java:49, 76, 117).
- `RateLimitFilter` keys groups on `getServletPath()` (RateLimitFilter.java:90).
- `WalletStartRequests` matches `^/broker/([^/]+)$` on it (WalletStartRequests.java:31).
- `WalletRequestBodyLimitFilter` matches the raw URI (:56-73).
- Spring's `PathPattern` matching compares decoded segments, and `StrictHttpFirewall` does not block `%6F`.

So `GET /realms/r/br%6Fker/eudi-wallet` would reach the broker start without the `wallet-start` limit, and
`/realms/r/%6Fid4vp/...` would skip the body limit (Tomcat's 2 MB form cap still applies) and the
`/oid4vp` limit. That voids the T18 store-fill DoS fix: a 10k in-memory cap filled means a 503 for every
wallet login.

The same root cause probably lets `/l%6Fgin` skip the pre-existing login brute-force limit. That makes it a
general issue, not only a wallet one. It is in the ledger (T18 ruling, "→ final triage with #10") but **not
in DEFERRED-SECURITY-WORK.md**.

Fix: decode and normalise `rest` in `RealmRoutingFilter`, or answer 400 for an encoded unreserved character.
Add an e2e test: `/realms/master/br%6Fker/<wallet>` 31× → 429.

### Minor (do before merge if cheap, otherwise backlog)

- **m1. CHANGELOG lists only "Added: EUDI Wallet".** These branch changes affect operators and are missing:
  - federated session-id rotation (T2);
  - `acr` in ID tokens for eID/wallet (T3);
  - **IdP secrets moved to encrypted `secret_json` (V75/V75.1) and no longer returned by the admin API.** This
    is an API change for any client that reads secrets back, such as the Terraform provider.
  - the Nimbus 10.10 bump for CVE-2025-53864;
  - the broker start now turning any provider `RuntimeException` into `error=federation` (T19 parked #4).
- **m2. Every rejected presentation shows the same browser copy:** `wallet.status.failed` = "Your wallet did not
  share your identity". This is wrong for a revoked, expired or untrusted credential, where the user did share.
  Use neutral copy: "We could not verify your wallet's identity".
- **m3. One undecryptable `secret_json` row fails `list(realm)`** (`IdentityProviderConfigService.toDto`). That
  takes down every store-backed provider of the realm in `refresh`, because `buildQuietly` only guards the
  factory. T4 introduced this; it is not pre-existing. Catch per row in `toDto`/`load`.
- **m4. The fail-open status audit (`WALLET_STATUS_CHECK_FAILED`, decision=accepted) carries no transaction id**,
  so an operator cannot tie a fail-open to a login (T10 #9).
- **m5. DEFERRED-SECURITY-WORK's "non-strict tdate parsing tolerance" looks stale.** The T12 fix round made tdate
  strict (MobileSecurityObject.java:287-292).
- **m6. The two §15 code conflations** (see §2) must go into the PR deviation list.

---

## 4. Spec compliance (whole feature)

| §15 criterion | Status |
|---|---|
| Configure via YAML **and** stored path; appears on login page with icon | YAML ✅. Stored ✅ for master only, ❌ multi-realm (**F1**). |
| Cross-device QR → logged in, ID token has PID claims + `acr` high | ✅ (T23 matrix, T25 live run). Claims are mapped at JIT; an Existing login syncs no attributes (by design). |
| Same-device → `/broker/{alias}/callback` → logged in | ✅ |
| Both formats succeed; either satisfies default `credential_sets` | ✅ (both via the in-repo TestWallet only; see the interop triage). |
| Each listed rejection: distinct code + friendly UI + audit | ⚠️ Codes distinct except the two documented conflations (**m6**). UI copy is one generic message (**m2**). Audit ✅, except the step-up path (**F2**). |
| `direct_post` refused under the production readiness check | ✅ (ProductionReadinessCheck plus validator). |
| No PID, token, nonce or key in logs; capturing test | ✅ (`WalletLogHygieneE2eTest`, both formats plus JIT/upgrade/LINK). |
| Redis concurrent duplicate `direct_post` → exactly one success | ✅ (T16 race tests). |
| Full suite green; CodeQL/dependency scan clean or triaged | Suite green per ledger (3996+39). CodeQL **not run locally**; CODEQL-TRIAGE.md notes the pending GitHub run. That run is a merge gate. |
| Docs: eudi-wallet.md, FEATURES (Experimental), CHANGELOG, VENDOR-MAP, SECURITY-REVIEW | ✅ present. CHANGELOG incomplete (**m1**). |

All five maintainer decisions are honoured:
- the "admin number, else link" subject strategy;
- the eIDAS ladder, with `EUDI_WALLET` as a tag only;
- pure Java, no Kotlin;
- no `NONE` strategy or step-up flow;
- the "Experimental" label.

The spec deviations (client_id `x509_hash` default, `statusList.required=false`, `accessKeyRef` rename, the
`RealmSigningKeys` software-only seam) are ruled and documented.

---

## 5. Merge readiness with `fix/pre-1.0-security`

`git merge-tree` reports **11 conflicted files**:

- `pom.xml`
- `IdentityProviderAdminController.java`
- `FederatedLoginCompleter.java`
- `EidScheme.java`
- `FlowController.java`
- `RateLimitConfig.java`
- `RateLimitFilter.java`
- `ProductionReadinessCheck.java`
- tests: `IdentityProviderAdminControllerTest`, `FederatedLoginCompleterTest`, `FederationProviderFactoryTest`,
  `ProductionReadinessCheckTest`

Expected interactions:

- **M1. Every wallet login is refused after the merge. `EidLevelOfAssurance` merges cleanly, but the semantics
  break.**
  - The security branch's `meetsMinimum` resolves the minimum through
    `canonicalMinimum(scheme, minimum)`, which looks up `LADDERS.get(scheme)` / `KEYWORDS.get(scheme)`.
  - `EUDI_WALLET` has neither entry. Only the wallet's `rung()` delegates to EIDAS.
  - So `meetsMinimum(EUDI_WALLET, LOA_HIGH, "http://eidas.europa.eu/LoA/high")` returns `false`.
  - `WalletAttributeMapper.satisfiesMinimumLoa` (WalletAttributeMapper.java:311-316) therefore refuses every
    presentation (default `minimumLoa` = high) with `INVALID_RESPONSE`.

  Fix: apply the same `EUDI_WALLET → EIDAS` delegation in `canonicalMinimum`. The wallet's own double guard then
  becomes redundant but harmless, and `WalletConfigValidator` can use `isValidMinimum`. The wallet tests will
  catch this, but it must not be "fixed" by loosening the guard.
- **M2. RateLimitFilter.** The security branch deletes the static `clientIp()`. The wallet's `Rule` loop,
  `anyMethodGroup` key and `tooMany` log (RateLimitFilter.java:81, 101, 112) all call it. Route all three
  through `clientIps.resolve(request)` and thread `ClientIpResolver` into the 3-arg and 4-arg constructors and
  into `RateLimitConfig`. This closes the XFF bypass of the wallet buckets. It does **not** close F3.
- **M3. FederatedLoginCompleter.**
  - The security branch rotates at flow start (`getSession(true)` + `changeSessionId()` +
    `MfaSessionState.clear`). The wallet rotates again in COMPLETED. Keep one.
  - The security branch adds COMPLETED + `mustEnrol` → `redirect:/mfa/enable` with an `MfaAuthentication`.
    On that path:
    - the wallet's `pendingCommit` (upgrade link) and `acr` are dropped, because the enrolment completion does
      not know the flow state;
    - **`WalletLoginCompleter.isCompletedLogin` classifies `redirect:/mfa/enable` as a success**, which makes
      T22 minor #1 real.

  Resolution: export the enrolment view as a pending view, treat it like `STEP_UP_VIEW`, and promote
  acr/commit/audit when enrolment completes (same mechanism as F2). Or refuse the wallet login until the user
  has enrolled.
- **M4. FlowController.** The security branch adds `unlockUser(flowUser)` refusal plus `changeSessionId`. The
  wallet adds `changeSessionId` plus pendingCommit plus pendingAcr. Merge order: user check → rotate (once) →
  commit-or-undo → `stamp` → pendingAcr.

  **Residual of the ledger's `submitChallenge` item:**
  - `MfaService.unlockUser(expected)` returns `true` when **no** `MfaAuthentication` is pending.
  - `FLOW_STATE` is overwritten by password login, but not by magic-link or other non-flow logins, and it is
    not removed on COMPLETED.
  - So a stale wallet flow state of user A could still promote A's `pendingAcr` (eIDAS high) into a session
    fully authenticated as B, if the actor also passes A's challenge.

  Tighten: require that the pending authentication is an `MfaAuthentication` for `state.userId`, or that the
  current principal equals `state.userId`, and remove `FLOW_STATE` on COMPLETED.

  Test fallout: the wallet's `FlowControllerPendingCommitTest` mocks `MfaService`. The new
  `unlockUser(String)` returns Mockito's default `false`, so those tests take the refusal path until they are
  stubbed. `FederatedLoginCompleter*Test` need the new constructor argument.
- **M5. AttributeEncryption fail-closed.**
  - The wallet's guards (pepper "decrypt returned input unchanged → refuse", the key-store probes) stay correct.
    They become belt and braces.
  - Wallet components build `new AttributeEncryption(key)` with the single-argument constructor, so they stay
    fail-closed even under `HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT=true`. That is the right outcome for a pepper.
  - The security branch treats a blank `DB_ENCRYPTION` as no key, which fixes the empty-key `SecretKeySpec`
    throw on this branch.
  - New failure mode: `IdentityProviderSecretsMigrator`'s per-row "unreadable → skip"
    (IdentityProviderSecretsMigrator.java:62-67) now throws instead. One bad row aborts the whole backfill.
    Wrap the per-row decrypt.
  - m3 becomes "throws from the converter" instead of "throws from JSON": same blast radius.
- **M6. EidScheme / IdentityProviderAdminController / FederationProviderFactory.** Keep `EUDI_WALLET` and the
  security branch's `of()` / `isEidProtocol()`. Make sure `isEidProtocol` stays false for the wallet protocols,
  so the eID-minimum validation at save and at build never runs on wallet rows. Merge both validators in the
  admin controller.
- **M7. MfaEnabledCondition fix.** Wallet logins of MFA-enabled users now challenge. Re-run the wallet e2e and
  acceptance tests with an MFA-enabled user: acr promoted, upgrade link committed after the step-up, and the
  audit from F2.
- **M8. pom.xml.** Both branches pin Nimbus 10.10. Keep one `dependencyManagement` entry and both comments. The
  security branch brings `NimbusNestedJsonRegressionTest`.
- **M9. ProductionReadinessCheck.** Union of the constructor parameters: the wallet's `FederationProviderProperties`
  and the security branch's migrate-until and trusted-proxy checks.
- **M10. HostAllowListFilter / trusted proxies.**
  - The wallet builds every URL from `idp.base.url`, never from the request, so there is no conflict.
  - Phones reach the IdP-base host, which is allowed.
  - A sandbox demo on a non-localhost host needs `HELIX_ALLOWED_HOSTS`.
  - `docs/eudi-wallet.md` §4 ("Not present on this branch") and the pre-existing-findings section of
    DEFERRED-SECURITY-WORK (four items) become stale. Rewrite them in the merge commit.

---

## 6. Triage of every deferred, parked and FINDING item in the ledger

Legend: **Fix** = before merge (or at merge, where noted). **Defer** = keep open, and it must be listed where
noted. **Drop** = resolved, not worth tracking, or cosmetic.

| # | Ledger item | Verdict | Reason / where tracked |
|---|---|---|---|
| T1-a | x509_hash padding UNVERIFIED | Drop | Settled (OpenID4VP §1.2, no padding); folded in. |
| T1-b | status-list vectors lack `source`; ARF quote wrapping | Drop | Cosmetic, docs-only. |
| T2-a | Test names promise rotate-before-persist but don't assert order | Drop | The security merge rewrites this ordering; re-pin it then (M3). |
| T2-b | Stale comment and duplicated stubbing in FederatedLoginCompleterTest | Drop | The file conflicts in the merge; clean it there. |
| T2-c | Password+MFA logins rotate twice | Drop | Harmless. Collapse duplicate rotations in M3/M4. |
| T2-d | FlowControllerTest outside fast filter | Drop | Test hygiene. |
| T3-a | Duplicated stash block, FQCNs, helix_acr naming | Drop | Style. |
| T3-b | acr-only binding guard untested | Defer | One unit test on `SsoSessionBindingAuthorizationService` (sid/authTime null, acr set). Backlog. |
| T3-c | **FlowController.submitChallenge doesn't check state.userId vs principal** | **Fix at merge** | Mostly fixed by 5904c42 on the security branch. The residual (no pending MfaAuthentication → `unlockUser` true; stale FLOW_STATE) needs the M4 tightening. |
| T3-d | e2e stub passes loa directly | Drop | The wallet path uses typed LoA end to end (T23/T25). |
| T4-a | PUT changing protocol keeps old protocol's secrets | Defer | Encrypted and unreachable. Add to backlog / DEFERRED (not listed). |
| T4-b | `IdentityProviderConfig` record toString prints merged secrets | Defer (cheap Fix recommended) | Not logged anywhere today (grepped). A latent leak; override toString. Not listed: add it. |
| T4-c | LDAP detail page `bindPassword` vs wizard `bindPw` badge | Defer | The backend reads `bindPassword` then `bindPw`, so writes work. The badge is wrong for wizard-created rows. UI backlog. |
| T4-d | Backfill without lock; duplicate WARN banners; e2e hardcodes key | Drop | Idempotent. The security branch replaces the banner. Test-only. |
| T5-a | realmId length / PEM caps → DataIntegrityViolation | Drop | PEM caps now `@Size` on `VerifierKeyImportRequest`; realmId is a path variable checked against existing realms. |
| T5-b | `encrypted` name collision; parseChain branch uncovered | Drop | Style / unreachable. |
| T6-a | StrictCbor budget per call, not per document | Drop | Resolved by T12 (CborLimits threaded; tag 24 decoded only at spec positions). |
| T6-b | Head-byte defensive check untested | Drop | Defensive. |
| T6-c | **Self-made mdoc DeviceResponse vector / "real interop vector needed"** | **Defer** (to Phase 4, with a precondition) | The SessionTranscript is pinned to OpenID4VP B.2.6.1 exactly. Everything else in the mdoc path (IssuerSigned tag-24 encoding, MSO digests, DeviceAuthentication) has only been checked against our own TestWallet, so a shared misreading would pass. It fails closed (interop risk, not security). Listed in docs/eudi-wallet.md §8, phase-2 summary open question 3, and ROADMAP Phase 4. Precondition: before the "Experimental" label is removed, add one third-party DeviceResponse vector (ISO 18013-5 Annex D as reproduced in an Apache-2.0 suite, after a licence check) or an EU reference-wallet capture. |
| T6-d | VerificationContext byte[] equals | Drop | Record equality is never used. |
| T7 | SOFT_FAIL ≥2 intermediates; blocked URL skips revocation; test leaks system props | Defer | Listed in DEFERRED ("bounded issuer-revocation client"). |
| T8-a | Disclosed claim named `_sd_alg` leaks into resolved output | Drop | Unrequested names are dropped by DCQL before mapping. No path to attributes. |
| T8-b | No trailing-`~` test; size counts chars not bytes; digest error code | Drop | The body limit bounds bytes; cosmetic. |
| T9-a | Clock-edge tests; aka_vcts vs HAIP -13; RSA_PSS guard duplicate | Drop | aka_vcts acceptance is scoped by the per-provider PID anchors (documented); rest cosmetic. |
| T9-b | Missing / non-integer `idx` test gap | Drop | Correct by inspection; cheap to add opportunistically. |
| T10 #5 | Status cache ~128 MB worst case | Defer | Listed in DEFERRED. |
| T10 #6 | Guard DNS outside fetch deadline | Defer | Listed in DEFERRED. |
| T10 #9 | UNAVAILABLE_ACCEPTED visibility in login audit | Defer | Emitted as WALLET_STATUS_CHECK_FAILED, but without txId (**m4**). Add to DEFERRED. |
| T10 #10 | Split CWT class | Drop | Maintainability only (listed anyway). |
| T11 #2,#4,#5,#7,#8,#9 | tdate, single-cert x5chain, version pin, byte[] equals, DeviceSignature negative test, internal Nimbus ECDSA helper | Defer | Listed in DEFERRED. #2 looks fixed by T12 (**m5**: update the list). #9 is guarded by the Nimbus pin plus tests. |
| T13 | RSA-OAEP literal test, null-input test | Drop | Test polish. |
| T14 #5, #7 | No mdoc end-to-end in matcher test; Set.copyOf order | Drop | #5 is covered by the T23 acceptance matrix (both formats); #7 cosmetic. |
| T16-a | No PostgreSQL wallet transaction store (queue + multi-replica) | Defer | Documented in docs §3 with a startup WARN. Add a ROADMAP line (not present). |
| T16-b | issueResponseCode crash window | Drop | Accepted ruling; self-expires ≤ 900 s. |
| T19 #1 | Shared-root §6.5 pin test | Defer | Listed in DEFERRED, docs §7.1, SECURITY-REVIEW B.6. |
| T19 #2 | CA cert as list leaf refused | Drop | Fail-closed by design. |
| T19 #3 | Persist normalised protocol | Drop | `fromStored` normalises on read. |
| T19 #4 | Broker start catches RuntimeException for all protocols | Fix (docs) | Add to CHANGELOG (**m1**). |
| T19 #5 | tx id only at DEBUG on refusal | Drop | The broker logs WARN with the reason; the audit carries the tx id. |
| T20-a | Cross-format conflict and insufficient LoA use INVALID_RESPONSE | Drop | Not among the §15 listed rejections; the detail is in the log. |
| T20 FINDING | **`meetsMinimum` unknown minimum treated as met** | **Fixed on the security branch, but Fix at merge (M1)** | 676fcc5 fixes eID. The merge breaks the wallet unless `canonicalMinimum` delegates EUDI_WALLET → EIDAS. |
| T21a FINDING | **AttributeEncryption plaintext fallback** | Fixed on the security branch (c419a9a, ab89269) | The wallet's own guards stay correct (M5). Per-row decrypt in the migrator needs a try/catch at merge. |
| T21a | Pepper / verifier-key rows on realm deletion | Defer | No realm-delete operation exists in this codebase (grepped). Tie cleanup to whichever feature adds realm deletion, and add a ROADMAP note. Without cleanup, a reused realm name would inherit the previous realm's RP access key. |
| T18 #10 | **X-Forwarded-For trust in RateLimitFilter** | Fixed on the security branch (b96284c) | Wire the wallet rules to `ClientIpResolver` at merge (M2). |
| T18 | %-encoded path bypass of `/oid4vp` filters | **Fix** (**F3**) | Not in DEFERRED; confirm with a test. |
| T18 | Concurrent-start leak (rate-bounded) | Drop | Bounded once F3 and M2 land. |
| T18 | NL-copy screenshots unverified | Defer | UI backlog; strings exist in messages_nl. |
| T18 | `Error` (not RuntimeException) from a committer escapes with session persisted | Defer | Listed in DEFERRED / SECURITY-REVIEW B.9. |
| T18 | WalletE2eFixture javadoc overstates | Drop | Test docs. |
| T18 FINDING | **Federated logins skip post-broker MFA step-up** | Fixed on the security branch (633d944) | Merge consequence: F2 becomes universal, and M7 re-tests are needed. |
| T21b I1 | JSON identities API unlinks wallet without reauth | Drop | Fixed (7269391). |
| T21b M1/M2 | QR-relay and reverse linking-CSRF residuals; "wallet linked" notification | Defer | Documented in docs §6.3 and SECURITY-REVIEW B.1. Add the notification to ROADMAP (not present). |
| T21b M3–M10 | Code spent before user-mismatch refusal; tuple/number owner divergence; binding key shared login/link; no resume after reauth; ambiguous multi-provider error; naming; link page → bare /login; line length | Defer (M5, M6, M9 UX backlog) / Drop (rest) | All fail safe. |
| T21b | `isWallet` catches only IllegalArgumentException | Defer | Listed in DEFERRED / B.9. |
| T22 #1 | `isCompletedLogin` is a blocklist | **Fix at merge** | Becomes a real bug with the security branch's `/mfa/enable` view (M3). Switch to an allowlist, or export pending views. |
| T22 #2–#4 | Replay audit without txId; 8 params; List.toString in fatal message | Drop | Low value. |
| T22 | WALLET_STATUS_CHECK_FAILED detail shape | Drop | Consistent and documented. |
| T24 M1–M14 | Console minors | Defer (M2, M9, M10, M12) / Drop (rest) | M2 is unreachable today but guard it. M10: EidAssurancePage "Add" offers the wallet. UI backlog. |
| T24 | **21 pre-existing inline styles in other providers' wizard sub-forms** | **Defer** | Not introduced: 25 at base, 21 at HEAD, so the branch removed 4. The console has hundreds elsewhere (AccountApp, SecurityTab, AppShell...). The wallet's own form is inline-style-free. A console-wide debt item, not a merge gate. Add a ROADMAP / console-debt line. |
| T24 | Choice row / `.hx-btn` < 44 px console-wide | Defer | Console-wide, pre-existing. |
| T25 FINDING | **`helix.federation.store.enabled` default off; startup loads master only** | **Fix** (**F1**) | Worse than recorded: each refresh wipes the other realms, default aliases collide, and the login page is unfiltered. The docs workaround is harmful. |
| T26 | GDPR / docs | Drop | Covered by this review (§7). |

---

## 7. Docs accuracy (docs/eudi-wallet.md, spot-checked against the code)

These claims are accurate:
- the verifier-key import endpoint and fields;
- `software:<realm>/<name>`;
- the defaults: `x509_hash`, `haip-vp`, `direct_post.jwt`, 300 s, `statusList.required=false`,
  `ADMINISTRATIVE_NUMBER`, high;
- the Redis vs in-memory selection and the WARN text;
- `POST /account/wallet/link`;
- the `deviceMac` rejection line (MdocPresentationVerifier.java:469-470);
- the fail-open/closed matrix;
- the subject rules §6.1/6.2.

These need correcting:
- **§2.2 (lines 63-76).** The "re-save after every restart" workaround is harmful, because every refresh
  replaces all realms' store-backed providers (F1). "Refreshes the live registry **for that write's own realm**"
  is true but incomplete: it also unloads every other realm.
- **§4** and the DEFERRED "pre-existing findings" section are stale once the security branch merges (M10).
- **DEFERRED** is missing three items: T11 tdate is stale (m5); the %-encoding bypass (F3) is absent; the
  status-audit txId gap (m4) is absent.
- **CHANGELOG** is incomplete (m1).

---

## 8. Declined to judge

| Item | Reason |
|---|---|
| Line-by-line cryptographic correctness of the SD-JWT, KB-JWT, COSE, MSO and JWE verifiers | Covered by the T6–T14 adversarial per-task reviews; outside a seam review. |
| Whether cross-device QR should ship at all (ARF OIA_08c) | A maintainer decision, documented as an open question. |
| SD-JWT VC -13 vs -19 and TSL -14 vs -21 differences (UNVERIFIED) | Needs the normative texts; Phase 4. |
| UI/UX visual quality | Signed off by independent Playwright reviews (T18, T21b, T24). |
| Cross-realm use of non-wallet store-backed providers (an OIDC connection of realm A usable from realm B's login page) | Pre-existing isolation behaviour of the alias-keyed registry; outside the wallet. It interacts with F1's fix, so flag it to the owner. |
| Carrier-NAT effect of the per-IP `/oid4vp` budget (120/min) | An operational tuning question; it is configurable. |
| Same-device flow when the wallet opens a different browser than the one that started (binding fails closed) | Inherent to browser binding (§10.1); a UX limitation, not a defect. |
| Runtime behaviour of F3 | Not executed (read-only review); flagged as "confirm with a failing test". |
