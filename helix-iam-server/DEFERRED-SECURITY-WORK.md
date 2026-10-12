# Deferred security work (tracked, not-yet-done)

These security-review / pentest items are deliberately NOT fixed in the current pass, with rationale.
Everything higher-severity has been remediated (see `SECURITY-REVIEW.md` and the internal test reports under
[`docs/security/`](../docs/security/)).

## M7 — OpenSAML 4.3.2 is EOL (upgrade to 5.x)
**Status: FIXED (2026-09-17) — the entire OpenSAML stack now runs on the current 5.1.4 line; EOL cleared.**

The upgrade did NOT, in the end, require moving Spring Security or Spring Boot. HelixIAM was found to use
OpenSAML **directly** (the `idp/saml`, `federation/saml`, `federation/eid` packages) and to reference **no**
`org.springframework.security.saml2` class at all — `spring-security-saml2-service-provider:6.5.10` was only
ever on the tree to drag OpenSAML onto the classpath. `spring-security-saml2-service-provider:6.5.10`, though
compiled against OpenSAML 4, is classpath-compatible with the 5 line, so the whole OpenSAML stack was forced
to **5.1.4** via `dependencyManagement` (with the old `net.shibboleth.utilities:java-support` excluded from it).

**Versions now on the tree:**
- `org.opensaml:*` **5.1.4** (was 4.3.2) — note `opensaml-core` split into `opensaml-core-api` + `opensaml-core-impl` in 5.x.
- `net.shibboleth:shib-support` / `shib-security` / `shib-networking` / `shib-velocity` **9.1.4** — replaces `net.shibboleth.utilities:java-support:8.4.2` (the `net.shibboleth.utilities.java.support.*` → `net.shibboleth.shared.*` repackaging).
- `org.apache.santuario:xmlsec` **3.0.5** (was 2.3.4).
- `org.cryptacular:cryptacular` **1.2.6** (was 1.2.5). BouncyCastle stays uniformly at **1.81** (direct pins, nearest-wins) so cryptacular's transitive bcprov:1.76 does not reintroduce the split-version `OperatorHelper` NoClassDefFoundError.

**Validation strength is unchanged.** Only two source imports moved
(`net.shibboleth.utilities.java.support.xml.{ParserPool,SerializeSupport}` → `net.shibboleth.shared.xml.*`);
every `org.opensaml.*` API HelixIAM uses is identical between 4.3.2 and 5.1.4, so signature validation
(`SAMLSignatureProfileValidator` + `SignatureValidator`), decryption (`Decrypter`), and the
conditions/issuer/recipient/status checks are byte-for-byte the same logic. The XXE/DTD hardening is provided
by OpenSAML's default `GlobalParserPoolInitializer` `BasicParserPool` (`disallow-doctype-decl` +
`secure-processing`), which HelixIAM never overrides and which is identical in java-support 8.4.2 and
shib-support 9.1.4 (verified by decompilation). All **1096** tests pass, including every SAML/eID security
test (unsigned/wrong-key rejection, replay, audience, SAML-1/S-H1/S-H2/SAML-3 conditions/issuer/recipient/status,
eID LoA + EncryptedID decryption). Boot-verified: the SAML IdP metadata + SSO endpoints and OIDC discovery all
come up on OpenSAML 5.

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

## EUDI Wallet: bounded issuer-revocation client (follow-up to Task 7, 2026-10-11)
**Status: OPEN.** `IssuerTrustValidator` (wallet issuer X.509 trust) lets the JDK `PKIXRevocationChecker` fetch the
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
  knowing. Documented here and in `docs/eudi-wallet.md` §7.1 and `SECURITY-REVIEW.md` Appendix B.6 (ledger:
  "parked for final triage/T26 docs", Task 19, which asked for both the documentation and a pinning test). **The
  documentation is this task's deliverable; the pinning test is not added here** — Task 26 is scoped to
  documentation, the security-review write-up and GDPR, not new wallet test coverage for a pre-existing, already
  openly-accepted trust-model case. Add the test alongside any future change that touches `MdocStatusListSigner`.
- **Status-list cache worst-case memory (~128 MB).** `TokenStatusListClient`'s verified-token cache has no
  overall byte budget, only a per-entry decompressed-size cap (2 MB) and a count/TTL-driven eviction; a verifier
  configured with many distinct, long-`maxCacheSeconds` status lists could accumulate a large working set before
  eviction catches up. Task 10 review finding #5, deferred to final triage.
- **`OutboundUrlGuard`'s DNS resolution is not itself inside the fetch deadline.** The guard resolves and checks
  a status-list host before the HTTP client's own connect timeout starts counting, so a slow-to-resolve (or
  deliberately slow) DNS name can extend a status check beyond the configured 3 s connect / 5 s read bounds.
  Task 10 review finding #6, deferred to final triage.
- **`StatusListToken`/CWT status-list parsing could be split into its own class.** Today the CWT (mdoc) status
  list form's COSE/CBOR handling is inlined alongside the SD-JWT (JWT) form in the same client rather than
  factored into a dedicated type. Not a defect — a structure/maintainability item. Task 10 review finding #10.
- **mdoc/COSE implementation-detail minors carried from the Task 11/12 reviews**, all accepted-risk or
  test-coverage gaps rather than defects, kept for a future pentest pass: an assumption that an `x5chain` is encoded as a single certificate when only one is present (vs. always an
  array), no explicit CBOR/COSE library version pin test, `byte[]` (non-constant-time) equality on a couple of
  internal comparisons that are not on a secret-comparison path, no dedicated negative test for a malformed
  `DeviceSignature`, and reliance on an internal Nimbus ECDSA helper rather than a public API for one signature
  check. Full detail in `task-11-review.md` (items #2, #4, #5, #7, #8, #9) and `task-12-review.md`.
- **Resolved (final review F1): `isWallet`/`isWalletAlias` caught only `IllegalArgumentException`.**
  `AccountIdentityController.isWallet` and `GdprAdminService.isWalletAlias` now ask
  `IdentityProviderRegistry#named`, which does not throw (it lists every realm's provider of that alias).
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

### Pre-existing findings outside the wallet, surfaced while building it, confirmed still open on this branch

These were found while reading the surrounding codebase for this feature; none were introduced by it and none
are fixed by it (confirmed against the current worktree, not merely carried over from an earlier note):

- **`AttributeEncryption.convertToEntityAttribute` returns an undecryptable value unchanged.** The *encrypt*
  path (`convertToDatabaseColumn`) now fails closed (see H2 above). The *decrypt* path's final fallback
  (`AttributeEncryption.java`, `tryLegacyDecryption`'s catch block) still logs a `WARN` and returns the stored
  string as-is when neither the current key nor the legacy key can decrypt it — correct for genuinely
  pre-encryption legacy rows, indistinguishable from a corrupted or tampered ciphertext. The wallet's own callers
  add their own guard where it matters (the realm wallet pepper fails closed when it cannot be decrypted), but
  the underlying converter itself does not, so any other caller that does not add a guard inherits this gap.
- **`EidLevelOfAssurance.meetsMinimum` treats an unrecognised minimum as met.** `rung(scheme, minimum)` returns
  `0` both for a blank/absent minimum and for a minimum string the ladder does not recognise; `meetsMinimum`
  requires `rung(asserted) > 0`, which means a garbage/unreachable `minimumLoa` behaves like "no minimum" rather
  than being refused outright. The wallet's own `WalletAttributeMapper.satisfiesMinimumLoa` was written
  defensively against exactly this, and `WalletConfigValidator` is believed to make a garbage `minimumLoa`
  unreachable for a wallet provider (it validates against the eIDAS ladder at config time) — but the shared
  `EidLevelOfAssurance` helper itself is unchanged and other callers (eID SAML) are not similarly guarded.
- **`RateLimitFilter` trusts `X-Forwarded-For` with no trusted-proxy restriction.** Confirmed unchanged
  (`RateLimitFilter.java:149-151`): the per-IP login/token/wallet rate limiters key off the first hop of
  `X-Forwarded-For` (else `X-Real-IP`, else the socket address) with no allow-list of which proxies may set it,
  so a client reachable directly (or behind an untrusted proxy) can forge a different apparent IP per request
  and evade the limiter — including the wallet's own `wallet`/`wallet-start` buckets. See `docs/eudi-wallet.md`
  §4: there is no `trustedProxies`/`allowedHosts` setting on this branch at all; it lives on a separate,
  not-yet-merged security branch.
- **Federated logins (including wallet logins) do not go through the same post-login MFA step-up a local
  password login does.** `MfaEnabledCondition` reads the `SecurityContext`, which is still empty at the point a
  `FederatedLoginCompleter`-driven flow begins evaluating whether to require a second factor. Surfaced during
  Task 18's review; not fixed here (it is not wallet-specific — every federation connector shares this gap).
- **Not reproducible (final review F3): a percent-encoded path skipping the wallet and login limits.**
  `RateLimitFilter` and `WalletRequestBodyLimitFilter` match the still-encoded path, so `/br%6Fker/<alias>` or
  `/%6Fid4vp/...` would not be counted — but StrictHttpFirewall refuses any `%`, `;`, `//` or `/./` with 400 (Tomcat
  refuses `%2F`), so no such spelling is served. Guarded by `WalletLimitPathEncodingE2eTest` (wallet start, `/oid4vp`,
  body limit) and `LoginRateLimitPathEncodingE2eTest` (sign-in). Relaxing the firewall would reopen it.
- **Resolved (final review F1):** admin-API/console-managed identity providers used to reach the live registry only
  with `helix.federation.store.enabled=true` (default `false`), only `master` was loaded at startup, and each write
  replaced every realm's store-backed providers with the written realm's. The store refresher is now on by default,
  loads every realm at startup, refreshes only the written realm, and keys stored providers by (realm, alias);
  see `docs/eudi-wallet.md` §2.2. Remaining: a write refreshes only the replica that handled it, and a realm import
  does not refresh the registry (both go live at the next restart).

## Deep SAML pentest (2026-09-17, issue #1) — outcome
Ran the deeper SAML coverage ([`docs/security/PENTEST-REPORT-SAML-DEEP-2026-09-17.md`](../docs/security/PENTEST-REPORT-SAML-DEEP-2026-09-17.md)). Result: 0 critical / 0 high / 1 medium / 2 low.
- **XSW2–XSW8**: ALL rejected on both the generic and eID validators (no signature-wrapping bypass). `InResponseTo` binding held; `EncryptedID` handling sound (no padding oracle / DoS).
- **DEEP-1 (MEDIUM) — FIXED**: the SAML-3 Response-`StatusCode`=Success check was missing on the eID POST path (`OpenSamlEidAssertionValidator`), so a validly-signed assertion inside an `AuthnFailed` response logged the user in. Ported `verifyStatusSuccess`; regression test `rejectsAValidlySignedAssertionCarriedInAFailedStatusResponse`.
- **DEEP-3 (LOW) — tracked**: the eID `ArtifactResponse` envelope signature is optional (the inner assertion signature is always enforced, so it is defense-in-depth). Revisit alongside the live DigiD mTLS work.
- **Still environment-blocked** (not a defect): the live DigiD `ArtifactResolve`/mTLS SOAP round-trip against a real peer, and the full seeded-broker end-to-end browser round-trip — need a DigiD test environment. Out-of-#1 lower items from the prior report (SP-SLO unsigned, rsa-sha1/unknown-SigAlg, unsigned SP metadata import) remain tracked.
