# Deferred security work (tracked, not-yet-done)

These security-review / pentest items are deliberately NOT fixed in the current pass, with rationale.
Everything higher-severity has been remediated (see `SECURITY-REVIEW.md` and the `PENTEST-REPORT-*` files).

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
