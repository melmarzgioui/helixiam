# Deferred security work (tracked, not-yet-done)

These security-review / pentest items are deliberately NOT fixed in the current pass, with rationale.
Everything higher-severity has been remediated (see `SECURITY-REVIEW.md` and the internal test reports under
[`docs/security/`](../docs/security/)).

## M7 — OpenSAML 4.3.2 is EOL (upgrade to 5.x)
**Status: DONE — OpenSAML 5.2.3 (latest 5.x).** First moved to 5.1.4 (2026-09-17), then to 5.2.3 (Dependabot),
and on 2026-10-13 the last OpenSAML 4 reference left the build: `spring-security-saml2-service-provider` was
removed. HelixIAM uses OpenSAML directly (SAML2 IdP `idp/saml`, SAML broker `federation/saml`, eID broker
`federation/eid`) and references no `org.springframework.security.saml2` class, so that module, whose 6.5.x POM
still depends on OpenSAML 4.3.2, was only dragging OpenSAML onto the classpath. The pom now declares
`opensaml-saml-api` / `opensaml-saml-impl` and `shib-support` directly.

**Versions on the tree** (no 4.x left; `mvn dependency:tree | grep -i opensaml`):
- `org.opensaml:*` **5.2.3** (`opensaml-core` is split into `opensaml-core-api` + `opensaml-core-impl` in 5.x).
- `net.shibboleth:shib-support` / `shib-security` / `shib-networking` / `shib-velocity` **9.2.3**, replacing
  `net.shibboleth.utilities:java-support:8.x` (`net.shibboleth.utilities.java.support.*` → `net.shibboleth.shared.*`).
- `org.apache.santuario:xmlsec` **3.0.6** and `org.cryptacular:cryptacular` **1.3.0**, the versions the Shibboleth
  17.2.3 parent of OpenSAML 5.2.3 is built with.
- BouncyCastle **1.86** (`bcprov`/`bcpkix`, direct pins, newer than the parent's 1.84), uniform so no split version.

Spring Security 6.5.11 builds its own `OpenSaml5*` support against OpenSAML 5.1.2; HelixIAM uses none of it, so
the 5.2.x line carries no Spring compatibility constraint. Validation logic is unchanged: signature profile +
`SignatureValidator`, `Decrypter`, conditions/issuer/recipient/status/InResponseTo checks, and the default
`BasicParserPool` XXE/DTD hardening. The full SAML/eID suites pass unchanged.

## Testing coverage gaps (not code defects — need more pentest depth)
- **XSW2–XSW8**: only XSW1 was scripted live (and rejected). The deeper signature-wrapping variants should be
  exercised in a follow-up pentest run.
- **eID EncryptedID decryption** and the **live DigiD ArtifactResolve mTLS SOAP back-channel** were not
  exercised (no live DigiD test peer). Cover when an eID test environment is available.
- **`/broker/{alias}/callback` end-to-end HTTP round-trip + RelayState gate**: the SAML pentest validated the
  assertion validator directly (stronger) but not the full browser round-trip; worth an integration test.

## Follow-up hardening (lower priority)
- **InResponseTo binding** — **DONE (issue #2)**. The inbound SAML broker now persists the outbound
  AuthnRequest id server-side (HTTP session, keyed by alias) at `start()` and restores it into the callback
  as `CallbackContext.expectedRequestId`. `OpenSamlAssertionValidator` binds it: when a pending request id
  exists (solicited / SP-initiated) the assertion's `InResponseTo` is REQUIRED and MUST equal it — an
  unsolicited or mismatched assertion injected into a solicited flow is rejected; the broker consumes the id
  per callback (single-use / replay-proof). With no pending id (unsolicited / IdP-initiated) the assertion is
  accepted only when the new `SamlProviderConfig.allowIdpInitiated` flag is set (default `false`, stored
  config key `allowIdpInitiated`). The broker's mandatory RelayState CSRF check already blocked direct-to-ACS
  unsolicited flows, so defaulting the flag off breaks no existing deployment. The `OpenSamlAssertionValidator`
  TODO(SAML-1/S-H1) is removed. Covered by `OpenSamlAssertionValidatorIntegrationTest` (match-accept,
  mismatch-reject, missing-on-solicited-reject, unsolicited-reject-when-disallowed, unsolicited-accept-when-allowed),
  `FederationBrokerControllerTest` (persist + bind + single-use consume), and `Saml2IdentityProviderTest`
  (start returns the id, callback threads it).
- **L5**: legacy AES/ECB decrypt fallback retained for existing-row compatibility (now logged).
- **L6**: generated bootstrap admin password is logged (zero-config trade-off; set `HELIX_ADMIN_PASSWORD`).

## SSRF: IPv6 addresses embedding a blocked IPv4 address (found 2026-10-13, all `OutboundUrlGuard` callers)
**Status: DONE (550d78d, 17d6c80).** `::ffff:127.0.0.1`, `::ffff:169.254.169.254`, IPv4-compatible `::/96`, NAT64
`64:ff9b::/96` and 6to4 `2002::/16` addresses are judged by their embedded IPv4 address; `192.0.0.0/24`,
`198.18.0.0/15`, `240.0.0.0/4` are blocked; `fd00:ec2::254` and broadcast are blocked even for allowlisted hosts.
Affected released versions (see `CHANGES-1.0.md`). Residual for non-wallet callers: the DNS-rebinding window of the
M6 finding remains where a JDK `HttpClient` re-resolves after `checkAllowed`.

## EUDI Wallet: bounded issuer-revocation client (follow-up to Task 7, 2026-10-11)
**Status: DONE (363fb26, branch `fix/wallet-network-hardening`).** `IssuerTrustValidator` no longer lets the JDK
`PKIXRevocationChecker` fetch anything. `IssuerRevocationClient` fetches OCSP and CRLs over `PinnedHttpFetcher` and
hands them to the JDK checker (OCSP via `setOcspResponses`, OCSP only; CRLs via a `CertStore` after a pre-check that
mirrors the JDK's CRL approval, so its hard-wired distribution-point fallback is never reached). Each residual limit
listed here before is closed:
- **DNS rebinding / TOCTOU — DONE.** `OutboundUrlGuard.resolveAllowed` resolves once and returns the checked
  addresses; the socket connects to one of them, with the original host as `Host` header and TLS name.
- **Redirects — DONE.** Never followed.
- **CRL size — DONE.** `helix.wallet.revocation.max-crl-bytes` (10 MB); OCSP responses at most 64 KB.
- **Result cache under our control — DONE.** Until `nextUpdate` (24 h cap), bounded by entries and bytes, shared by
  every provider.
- **SOFT_FAIL with two or more intermediates — DONE.** Every certificate is checked on its own against its own
  issuer; a revoked certificate anywhere refuses.
- Timeouts: connect 3 s, 5 s per fetch including DNS (inside the deadline), 10 s per chain. **Default mode:**
  `HARD_FAIL` (was `SOFT_FAIL`); configurable per provider, console field added. Rationale in
  `docs/eudi-wallet.md` §7.2.
- **Review follow-ups (2026-10-13) — DONE.** The first version relied on a pre-check to keep
  `PKIXRevocationChecker`'s hard-wired distribution-point fallback from running; a review proved it reachable.
  CRLs now go to the JDK's legacy checker with `com.sun.security.enableCRLDP=false` forced at startup and the
  relevant JVM settings checked before each use (b79b50b). Also: CRL clock skew equal to the JDK's 15 min (cc681c7),
  single-flight and a global fetch cap, 60 s negative cache for unparseable CRLs (8739d51), CRL cache sized by
  parsed heap (a7b28f9), `max-crl-bytes` capped at 100 MB (74b4fcf), strict HTTP framing (c198f98, 5664038),
  non-ASCII paths (258c6a6), headers validated before connecting (c433541), abort races (fc49b16, 66c4eae).

## EUDI Wallet: deferred/parked items (Task 26, 2026-10-12)

Compiled from the brief's own list plus every `Ruling:`/`FINDING`/"parked" entry in
`.superpowers/sdd/2026-10-09-eudi-wallet-openid4vp/progress.md` that is security-relevant. Items already covered
above (the bounded issuer-revocation client, L5, L6) are not repeated. See
`helix-iam-server/SECURITY-REVIEW.md` Appendix B for the full wallet threat model these items sit alongside.

### Wallet-specific, parked to this final review

- **Shared-root status-list anchor (§6.5 residual case).** When an mdoc's MSO signer and its status list's signer
  chain to a shared root that issues DS certificates directly (rather than through a dedicated intermediate per
  purpose), the §6.5 signer rule as implemented accepts it — standard for a per-issuer IACA anchor, but worth
  knowing. Documented here and in `docs/eudi-wallet.md` §7.1 and `SECURITY-REVIEW.md` Appendix B.6 (ledger:
  "parked for final triage/T26 docs", Task 19, which asked for both the documentation and a pinning test). **The
  documentation is this task's deliverable; the pinning test is not added here** — Task 26 is scoped to
  documentation, the security-review write-up and GDPR, not new wallet test coverage for a pre-existing, already
  openly-accepted trust-model case. Add the test alongside any future change that touches `MdocStatusListSigner`.
- **DONE (537289a) — Status-list cache worst-case memory (~128 MB).** `TokenStatusListClient`'s verified-token cache
  had no overall byte budget. `StatusListCache` now bounds entries and total decoded list bytes (LRU), shared by every
  provider: `helix.wallet.status-list.cache-max-entries` (64), `helix.wallet.status-list.cache-max-bytes` (32 MB).
  Task 10 review finding #5.
- **DONE (4b95470) — shared status-list cache consulted before the provider's own policy.** `vet()` (https,
  `allowedHosts`) now runs before the cache lookup. **DONE (7798cf9)** — a status-list TLS failure or malformed HTTP
  answer was transient and so could fail open; it fails closed now.
- **DONE (a7e55e4) — `OutboundUrlGuard`'s DNS resolution is not itself inside the fetch deadline.** Status-list
  fetches now go through `PinnedHttpFetcher`: the guard resolves inside the 5 s deadline and the connection goes to
  the validated address (also closing the rebinding window for status lists). Task 10 review finding #6.
- **DONE (9d42741) — `StatusListToken`/CWT status-list parsing split into its own class.** `StatusListCwt` holds the
  CWT (mdoc) form; `StatusListToken` keeps the JWT form and the common checks. No behaviour change, no test edited.
  Task 10 review finding #10.
- **mdoc/COSE implementation-detail minors carried from the Task 11/12 reviews**, all accepted-risk or
  test-coverage gaps rather than defects, kept for a future pentest pass: an assumption that an `x5chain` is encoded as a single certificate when only one is present (vs. always an
  array), no explicit CBOR/COSE library version pin test, `byte[]` (non-constant-time) equality on a couple of
  internal comparisons that are not on a secret-comparison path, no dedicated negative test for a malformed
  `DeviceSignature`, and reliance on an internal Nimbus ECDSA helper rather than a public API for one signature
  check. Full detail in `task-11-review.md` (items #2, #4, #5, #7, #8, #9) and `task-12-review.md`.
- **The fail-open status audit carries no transaction id.** `WALLET_STATUS_CHECK_FAILED` (decision `accepted`,
  emitted by `TokenStatusListClient` when an issuer's status list is transiently unavailable under
  `FAIL_OPEN_WITH_AUDIT`) has `{reason, statusListHost, decision}` but not the wallet transaction id, so an operator
  cannot tie a fail-open to the login it let through except by time and realm. Task 10 review #9 / final review m4.
  Fix: thread the transaction id into the status check's audit sink.
- **A PUT that changes an identity provider's protocol keeps the old protocol's secrets.** `IdentityProviderConfigService
  .saveOrUpdate` merges the stored `secret_json` with the incoming secrets by key; secret keys that belong only to the
  previous protocol stay stored (encrypted, never returned, and not read by the new protocol's provider). Task 4
  review. Fix: drop secrets that `ProviderSecretKeys` does not list for the new protocol.
- **`IdentityProviderConfig.toString()` prints the merged secrets.** The record's generated `toString` includes the
  `config` map, which on the runtime side contains the decrypted secrets. Nothing logs or formats it today (checked);
  a latent leak for a future log line. Task 4 review. Fix: override `toString` to redact `ProviderSecretKeys`.
- **`FederatedLoginCommit.commit` does not catch `java.lang.Error`.** By Java convention (the project does not
  catch `Error` anywhere else either), an `Error` thrown by a committer (the wallet's `WalletPendingLinkCommit`
  is the only implementation) escapes uncaught with the HTTP session already established a few lines earlier in
  `FederatedLoginCompleter.complete`. `RuntimeException` is caught and correctly refuses the login
  (`FederatedLoginCommit.java:44-55`); `Error` is not, and is not expected to be. See `SECURITY-REVIEW.md`
  Appendix B.9.

### Wallet items done (production readiness, 2026-10-13)

Moved here from the lists above and from the final review's parked items; each landed with tests on
`feat/wallet-production`. Details in `CHANGES-1.0.md` (next release) and `docs/eudi-wallet.md`.

- **DONE — identity-provider changes on every replica.** Final review F1 left: "a write refreshes only the replica that
  handled it, and a realm import does not refresh the registry (both go live at the next restart)". Every save and
  delete now bumps the realm's `idp_config_version` row (V78) in its transaction; every replica polls it
  (`helix.federation.store.poll-interval-seconds`, default 10) and reloads the realms that moved; a realm import
  reloads the importing replica at once. `IdentityProviderRegistryReplicasE2eTest` runs a second replica on the same
  database.
- **DONE — `FederationStoreRefresher.refresh` built outside the registry lock** (final re-review, parked minor): two
  concurrent writes could publish the older set. Publication is version-ordered: the realm's version is read before its
  configs and the registry refuses a set older than the one it holds
  (`FederationStoreRefresherTest.twoConcurrentRefreshes_neverPublishTheOlderSetOverTheNewer`).
- **DONE — broker session attributes keyed by alias only** (final fix ruling, deferred): two realms using alias
  `eudi-wallet` in one browser clobbered each other's state, binding and `HELIX_WALLET_TX_<alias>`. Now keyed by
  (realm, alias) (`BrowserBinding.sessionKey`); `WalletTwoRealmsOneBrowserE2eTest`.
- **DONE — no PostgreSQL wallet transaction store** (T16-a): a multi-replica `queue` deployment needed sticky sessions.
  `JdbcWalletTransactionStore` (V79) is the store on the `queue` session store and whenever no Redis is configured; it
  passes the shared contract suite including the 20-thread races. The in-memory store needs
  `helix.wallet.transaction-store=memory`.
- **DONE — "wallet linked" notification** (T21b M1/M2): the QR-relay and reverse linking-CSRF residuals stay
  inherent to cross-device flows, but the account owner is now emailed when a wallet is linked
  (`WalletLinkedNotice`, template `wallet-linked-notice`; no subject hash, no PID value).
- **DONE — cross-realm alias lookups** (final re-review, parked minor; and the F1 note that `isWallet`/`isWalletAlias`
  now ask `named`): `AccountIdentityController.isWallet` and `GdprAdminService.isWalletAlias` resolve the alias in the
  user's own realm first (`IdentityProviderRegistry#isWallet`) and fall back to every realm only for an alias that realm
  does not serve.
- **DONE — recovery-codes page after a refused pending commit** (final re-review, parked minor):
  `MfaAuthController.processEnableMfaFactor` now shows the federation error and issues no codes.
- **PARTLY DONE — third-party mdoc vector** (T6-c): IssuerAuth, MSO and digests are checked against EU reference wallet
  DeviceResponses (Apache-2.0). Still open: a third-party DeviceAuth with its SessionTranscript (see `ROADMAP.md`).
  Decided (maintainer ruling): a short device-key coordinate (one reference credential has a 31-byte `x`) is
  left-padded and accepted; longer or empty is refused, and the on-curve check is unchanged.

### Pre-existing findings outside the wallet, surfaced while building it — resolved by the merge of `fix/pre-1.0-security`

Four findings outside the wallet were surfaced while building it. All four are fixed on `fix/pre-1.0-security`, which
is merged into this branch; the wallet-specific consequences were resolved in the merge:

- **`AttributeEncryption` returned an undecryptable value unchanged** — fixed (c419a9a, ab89269): an undecryptable
  column fails the read; plaintext reads need their own time-boxed migration flag
  (`HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT` + `_UNTIL`). The wallet pepper and verifier key store keep their own
  fail-closed guards (they use the one-argument constructor, so the migration flag never applies to them). In the
  merge, `IdentityProviderSecretsMigrator` reads each row's stored secrets on its own, so one unreadable row is logged
  by id and skipped instead of aborting the backfill, and `IdentityProviderConfigService` skips an unreadable row by id
  instead of failing the realm's (or every realm's) provider load.
- **`EidLevelOfAssurance.meetsMinimum` treated an unrecognised minimum as met** — fixed (676fcc5): an unknown minimum is
  never met, and admin writes refuse it. In the merge, `canonicalMinimum` resolves `EUDI_WALLET` on the eIDAS ladder
  like `rung()` does (without it every wallet login was refused); the wallet's own `satisfiesMinimumLoa` guard stays.
  Wallet protocols are not eID protocols (`EidScheme.isEidProtocol`), so the eID minimum check never runs on them.
- **`RateLimitFilter` trusted `X-Forwarded-For` from anyone** — fixed (b96284c): `ClientIpResolver` reads it only from
  `HELIX_TRUSTED_PROXIES`. In the merge, the wallet's `/oid4vp` group and `wallet-start` rule key on the same resolver.
- **Federated logins skipped the post-login MFA step-up** — fixed (633d944): `MfaEnabledCondition` evaluates the flow's
  own user. In the merge, a wallet login that steps up (or must first enrol in MFA, `/mfa/enable`) keeps its pending
  upgrade link, `acr` and audit marker on the flow state and makes them when that step completes; `/flow` promotes only
  a pending sign-in of the flow's own user, and the flow state leaves the session on completion and on a magic-link
  sign-in, so a flow user A left behind can never complete into user B's session.
- **Not reproducible (final review F3): a percent-encoded path skipping the wallet and login limits.**
  `RateLimitFilter` and `WalletRequestBodyLimitFilter` match the still-encoded path, so `/br%6Fker/<alias>` or
  `/%6Fid4vp/...` would not be counted — but StrictHttpFirewall refuses any `%`, `;`, `//` or `/./` with 400 (Tomcat
  refuses `%2F`), so no such spelling is served. Guarded by `WalletLimitPathEncodingE2eTest` (wallet start, `/oid4vp`,
  body limit) and `LoginRateLimitPathEncodingE2eTest` (sign-in). Relaxing the firewall would reopen it.

## Deep SAML pentest (2026-09-17, issue #1) — outcome
Ran the deeper SAML coverage ([`docs/security/PENTEST-REPORT-SAML-DEEP-2026-09-17.md`](../docs/security/PENTEST-REPORT-SAML-DEEP-2026-09-17.md)). Result: 0 critical / 0 high / 1 medium / 2 low.
- **XSW2–XSW8**: ALL rejected on both the generic and eID validators (no signature-wrapping bypass). `InResponseTo` binding held; `EncryptedID` handling sound (no padding oracle / DoS).
- **DEEP-1 (MEDIUM) — FIXED**: the SAML-3 Response-`StatusCode`=Success check was missing on the eID POST path (`OpenSamlEidAssertionValidator`), so a validly-signed assertion inside an `AuthnFailed` response logged the user in. Ported `verifyStatusSuccess`; regression test `rejectsAValidlySignedAssertionCarriedInAFailedStatusResponse`.
- **DEEP-3 (LOW) — DONE (2026-10-13)**: the eID `ArtifactResponse` envelope signature is now REQUIRED and must verify
  against the IdP metadata signing certificate (`OpenSamlEidArtifactResolver.verifyResponse`); an unsigned envelope is
  refused, and any envelope is refused when the IdP's metadata gives no signing key. The inner assertion signature is
  still enforced as before. Covered by `OpenSamlEidArtifactResolverTest` (loopback ARS stub: signed accepted;
  unsigned, wrong-key and no-IdP-key refused). The live DigiD mTLS round-trip is still environment-blocked.
- **Still environment-blocked** (not a defect): the live DigiD `ArtifactResolve`/mTLS SOAP round-trip against a real peer, and the full seeded-broker end-to-end browser round-trip — need a DigiD test environment. Out-of-#1 lower items from the prior report (SP-SLO unsigned, rsa-sha1/unknown-SigAlg, unsigned SP metadata import) remain tracked.
