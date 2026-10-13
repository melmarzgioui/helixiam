# Deferred security work (tracked, not-yet-done)

These security-review / pentest items are deliberately NOT fixed in the current pass, with rationale.
Everything higher-severity has been remediated (see `SECURITY-REVIEW.md` and the internal test reports under
[`docs/security/`](../docs/security/)).

## Spring Boot 4: application code still on Jackson 2 (`spring-boot-jackson2`, deprecated)
**Status: OPEN (low).** The Spring Boot 4.1 upgrade (2026-10-13) closed CVE-2026-47884 / CVE-2026-47890 and moved
the server to a supported framework line. The application's own JSON code (`com.fasterxml.jackson`: controllers
returning `JsonNode`, the wallet's `StrictJson` / `StrictCbor`, ~400 files) deliberately stayed on Jackson 2.21.x,
auto-configured by Boot's `spring-boot-jackson2` module, with `spring.http.converters.preferred-json-mapper=jackson2`
keeping Spring MVC's wire format. Jackson 2.21 still receives fixes, but Boot ships the module deprecated and will
remove it in a future 4.x. Move to Jackson 3 (`tools.jackson`) before that, in its own change: Jackson 3's defaults
differ (e.g. alphabetical property order, `FAIL_ON_NULL_FOR_PRIMITIVES`, unchecked `JacksonException`), and the
wallet's strict parsers need their own review and tests. Spring Security 7, Flyway 12 and webauthn4j already use
Jackson 3 (3.2.3) internally.

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

Spring Security (6.5.11 then, 7.1.1 since the Boot 4 upgrade) builds its own `OpenSaml5*` support; HelixIAM uses none of it, so
the 5.2.x line carries no Spring compatibility constraint. Validation logic is unchanged: signature profile +
`SignatureValidator`, `Decrypter`, conditions/issuer/recipient/status/InResponseTo checks, and the default
`BasicParserPool` XXE/DTD hardening. The full SAML/eID suites pass unchanged.

## Testing coverage gaps (not code defects — need more pentest depth)
- **XSW2–XSW8**: **DONE** — all rejected on both validators in the deep SAML pentest (2026-09-17, below).
- **eID EncryptedID decryption**: **DONE (covered)** — exercised by the deep pentest and by
  `OpenSamlEidAssertionValidatorIntegrationTest` (a real signed DigiD response with an encrypted BSN, per level).
- **Live DigiD ArtifactResolve mTLS SOAP back-channel**: **still environment-blocked** (no live DigiD test peer). The
  envelope signature is now required (DEEP-3) and tested against a loopback ARS stub; the live round-trip waits for a
  DigiD test environment.
- **`/broker/{alias}/callback` end-to-end HTTP round-trip + RelayState gate**: **not a defect (test depth).** The
  pieces are covered where they decide: the SAML/eID assertion validators directly (stronger than a browser run),
  the mandatory RelayState/state CSRF check in `FederationBrokerControllerTest` and the provider tests, and the
  callback over real HTTP by `WalletFlowE2eTest` (state bound to the browser that started the login) and the federated
  browser e2e tests. A seeded SAML broker browser run would add depth, not close a known gap.

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
- **L5 — DONE (2d95f51).** `LegacyEncryptionBackfill` re-encrypts every legacy AES/ECB value of every
  `AttributeEncryption` column to AES-GCM at startup (idempotent, logged by row id only, unreadable rows skipped and
  named in a readiness WARN); afterwards the ECB fallback is off unless `HELIX_DB_ENCRYPTION_ALLOW_LEGACY=true`, so a
  legacy value fails closed. A legacy decryption must also be valid UTF-8 (review #10). Each column runs in its own transaction; a failed
  column is logged at ERROR, shown as a production-readiness WARNING and in the gauge
  `helix_db_encryption_legacy_failed_columns`, and keeps the fallback on (follow-up commit).
- **L6 — DONE (bd561bd).** The generated bootstrap admin password was already written 0600 to
  `HELIX_ADMIN_PASSWORD_FILE` (default `$TMPDIR/helixiam-admin-password`) with only the path logged; a whole-boot test
  now captures every log line and checks the password is in none of them and the file is 0600. The Helm notes and
  values no longer say it is logged; the README, chart README and compose file show how to read it.

## EUDI Wallet: bounded issuer-revocation client (follow-up to Task 7, 2026-10-11)
**Status: OPEN (owned by the separate revocation-client / status-list work).** `IssuerTrustValidator` (wallet issuer X.509 trust) lets the JDK `PKIXRevocationChecker` fetch the
CRL distribution points and OCSP responders named in the presented certificates. Mitigated today:
- Nothing is fetched until the chain validates to a configured anchor, so only certificates a trusted CA issued can
  name a URL.
- Every CRL/OCSP URL passes `OutboundUrlGuard` first. Non-http(s) schemes (incl. `ldap:`), non-URI names, and
  loopback, private and link-local hosts are never fetched.
- The JDK timeouts are bounded in `Application.main` (`RevocationTimeouts`: 3 s connect, 5 s read; an operator's
  `-D` value wins).

Residual limits of the JDK fetch, to be closed by a HelixIAM revocation client (guarded, time-bounded,
size-capped, CRL/OCSP response cache, plugged into PKIX via a custom `PKIXCertPathChecker` or pre-fetched CRLs in a
`CertStore`):
- **DNS rebinding / TOCTOU:** the guard resolves the host, then the JDK resolves it again before connecting.
- **Redirects:** the JDK's `HttpURLConnection` follows same-protocol redirects, which can lead to an address the
  guard never saw.
- **CRL size:** the JDK sets no download cap, so a large CRL is a memory and latency DoS.
- **No result cache under our control:** each wallet login may re-fetch, depending only on the JDK's internal
  caching.
- **SOFT_FAIL with two or more intermediates:** an undeterminable upper CA stops the JDK before it checks a lower
  CA. The leaf is always checked separately.

## EUDI Wallet: deferred/parked items (Task 26, 2026-10-12)

Compiled from the brief's own list plus every `Ruling:`/`FINDING`/"parked" entry in
`.superpowers/sdd/2026-10-09-eudi-wallet-openid4vp/progress.md` that is security-relevant. Items already covered
above (the bounded issuer-revocation client, L5, L6) are not repeated. See
`helix-iam-server/SECURITY-REVIEW.md` Appendix B for the full wallet threat model these items sit alongside.

### Wallet-specific, parked to this final review

- **Shared-root status-list anchor (§6.5 residual case).** When an mdoc's MSO signer and its status list's signer
  chain to a shared root that issues DS certificates directly (rather than through a dedicated intermediate per
  purpose), the §6.5 signer rule as implemented accepts it — standard for a per-issuer IACA anchor, but worth
  knowing. **Not a vulnerability:** an accepted, documented trust-model property of a per-issuer IACA anchor; the only
  open part is a pinning test. Documented here and in `docs/eudi-wallet.md` §7.1 and `SECURITY-REVIEW.md` Appendix B.6 (ledger:
  "parked for final triage/T26 docs", Task 19, which asked for both the documentation and a pinning test). **The
  documentation is this task's deliverable; the pinning test is not added here** — Task 26 is scoped to
  documentation, the security-review write-up and GDPR, not new wallet test coverage for a pre-existing, already
  openly-accepted trust-model case. Add the test alongside any future change that touches `MdocStatusListSigner`.
- **Status-list cache worst-case memory (~128 MB).** *(Status-list network item: owned by the status-list work.)* `TokenStatusListClient`'s verified-token cache has no
  overall byte budget, only a per-entry decompressed-size cap (2 MB) and a count/TTL-driven eviction; a verifier
  configured with many distinct, long-`maxCacheSeconds` status lists could accumulate a large working set before
  eviction catches up. Task 10 review finding #5, deferred to final triage.
- **`OutboundUrlGuard`'s DNS resolution is not itself inside the fetch deadline.** *(Status-list network item: owned by
  the status-list work.)* The guard resolves and checks
  a status-list host before the HTTP client's own connect timeout starts counting, so a slow-to-resolve (or
  deliberately slow) DNS name can extend a status check beyond the configured 3 s connect / 5 s read bounds.
  Task 10 review finding #6, deferred to final triage.
- **`StatusListToken`/CWT status-list parsing could be split into its own class.** Today the CWT (mdoc) status
  list form's COSE/CBOR handling is inlined alongside the SD-JWT (JWT) form in the same client rather than
  factored into a dedicated type. Not a defect — a structure/maintainability item, not a security issue. Task 10
  review finding #10.
- **mdoc/COSE implementation-detail minors carried from the Task 11/12 reviews**, all accepted-risk or
  test-coverage gaps rather than defects, kept for a future pentest pass: an assumption that an `x5chain` is encoded as a single certificate when only one is present (vs. always an
  array), no explicit CBOR/COSE library version pin test, `byte[]` (non-constant-time) equality on a couple of
  internal comparisons that are not on a secret-comparison path, no dedicated negative test for a malformed
  `DeviceSignature`, and reliance on an internal Nimbus ECDSA helper rather than a public API for one signature
  check. Full detail in `task-11-review.md` (items #2, #4, #5, #7, #8, #9) and `task-12-review.md`. **Not
  vulnerabilities:** a single-certificate `x5chain` is decoded either way and then chain-validated to an anchor; the
  `byte[]` comparisons compare public values; the version pin and the malformed-`DeviceSignature` test are coverage, and
  a malformed signature already fails the COSE verification it reaches.
- **DONE (b45e247): the fail-open status audit carries no transaction id.** The response handler now runs a
  presentation's verification inside its transaction (`WalletStatusAudit`), and the audit names its `transactionId`.
  Was: `WALLET_STATUS_CHECK_FAILED` (decision `accepted`,
  emitted by `TokenStatusListClient` when an issuer's status list is transiently unavailable under
  `FAIL_OPEN_WITH_AUDIT`) has `{reason, statusListHost, decision}` but not the wallet transaction id, so an operator
  cannot tie a fail-open to the login it let through except by time and realm. Task 10 review #9 / final review m4.
  Fix: thread the transaction id into the status check's audit sink.
- **DONE (3b7cc3b): a PUT that changes an identity provider's protocol keeps the old protocol's secrets.**
  `saveOrUpdate` now drops stored secrets the new protocol does not list. Was: `IdentityProviderConfigService
  .saveOrUpdate` merges the stored `secret_json` with the incoming secrets by key; secret keys that belong only to the
  previous protocol stay stored (encrypted, never returned, and not read by the new protocol's provider). Task 4
  review. Fix: drop secrets that `ProviderSecretKeys` does not list for the new protocol.
- **DONE (3b7cc3b): `IdentityProviderConfig.toString()` prints the merged secrets.** Both copies now redact every
  `ProviderSecretKeys` value. Was: The record's generated `toString` includes the
  `config` map, which on the runtime side contains the decrypted secrets. Nothing logs or formats it today (checked);
  a latent leak for a future log line. Task 4 review. Fix: override `toString` to redact `ProviderSecretKeys`.
- **DONE (3b7cc3b): `FederatedLoginCommit.commit` does not catch `java.lang.Error`.** `PendingFederatedLogin.finish`
  catches `Throwable` around the commit only, refuses the login (clears the context, invalidates the session, reports
  the failure) and then rethrows the `Error`, so the session is never left signed in. Was: By Java convention (the project does not
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
- **Still environment-blocked** (not a defect): the live DigiD `ArtifactResolve`/mTLS SOAP round-trip against a real peer, and the full seeded-broker end-to-end browser round-trip — need a DigiD test environment. Out-of-#1 lower items from the prior report: **SAML-4 (SP-SLO unsigned) — DONE
  earlier**: `SamlIdpController.processSlo` refuses SP-initiated SLO unless the SP has a registered signing certificate
  and the LogoutRequest signature verifies. **SAML-7 (rsa-sha1 / unknown SigAlg) — DONE earlier**:
  `SamlAuthnRequestParser.jca` accepts only RSA-SHA256/384/512 and rejects SHA-1, unknown and missing algorithms.
  **S-I1 (unsigned SP metadata import) — not a vulnerability**: the metadata is pasted or fetched by an authenticated
  realm admin, who is trusted to register the SP and its certificates at all (typing them in by hand has the same
  trust); metadata signing is optional in SAML deployments, and the import is admin-RBAC-gated and audited.

## Pre-1.0 security review residuals (2026-10-13, branch `fix/security-residuals`)
- **DONE (47b0ff1) — classic DigiD AuthnRequest.** Per Logius, *Koppelvlakspecificatie DigiD SAML Authenticatie*
  v3.5, Basis/Midden/Substantieel/Hoog are `PasswordProtectedTransport`/`MobileTwoFactorContract`/`Smartcard`/
  `SmartcardPKI`, requested with `RequestedAuthnContext Comparison="minimum"`. The DigiD keywords (`loa1`–`loa4`,
  `basis`/`midden`/`substantieel`/`hoog`) resolve to those classes in the request and the comparison; stored
  `urn:nl-eid-gdi:1.0:LoA:*` minimums keep their comparison and are requested as the oasis class of the same level
  (follow-up commit); brokers asserting them keep working. Review #8 closed.
- **DONE (67dd14b) — `/flow` enrolment rule.** A `/flow` completion in an MFA-required realm for a user who has not
  enrolled TOTP (an admin-built flow with email OTP, push or QR) now goes to `/mfa/enable` with the sign-in pending,
  like `FlowLoginSuccessHandler` and the federated completion.
- **DONE (4974628) — null expected user.** `MfaService.unlockUser(null)` already failed closed after the merge; pinned
  by `MfaServiceUnlockTest` (a null-safe-equals mutation turns it red).
- **DONE (333c2bf) — migration window at runtime.** `HELIX_DB_ENCRYPTION_MIGRATE_UNTIL` is enforced on every plaintext
  read: after the date, the read fails closed and an ERROR is logged.
- **DONE (9d27793) — Host header port.** Outside `dev`, a base-URL host accepts only that URL's port (or a `Host`
  without a port); `HELIX_ALLOWED_HOSTS` entries may pin `host:port`; an invalid port gets 400; probe exemptions apply
  only on the connection's own port or the scheme's default port. Review #6 follow-up.
- **Review findings left as they are (not in this file before; minor, no exploit path):** #3 (the by-id user lookup of
  `MfaEnabledCondition` is not realm-scoped, but its id only comes from server-side flow state, which the broker resolved
  realm-checked), #14 (documentation of right-most-untrusted XFF; the README already says never to list ranges clients
  connect from). Reviews #9 and #13 are closed below.
- **DONE (cb68519) — review #13.** `ClientIpResolver` no longer reads `X-Real-IP`, so a
  trusted hop that neither sets nor strips it can no longer let a client choose its own address.
- **DONE (dc24def) — review #9.** A realm import refuses an eID
  connection whose scheme or minimum level of assurance is unknown, with the admin API's field errors, instead of
  saving it and skipping it at load time.
