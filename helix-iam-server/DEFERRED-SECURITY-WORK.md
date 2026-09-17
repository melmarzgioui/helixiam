# Deferred security work (tracked, not-yet-done)

These security-review / pentest items are deliberately NOT fixed in the current pass, with rationale.
Everything higher-severity has been remediated (see `SECURITY-REVIEW.md` and the `PENTEST-REPORT-*` files).

## M7 — OpenSAML 4.3.2 is EOL (upgrade to 5.x)
**Status: deferred — coupled upgrade, needs dedicated effort + SAML integration testing.**

OpenSAML `4.3.2` is not a standalone dependency we can bump: it is pulled transitively by
`spring-security-saml2-service-provider:6.5.10`, and Spring Security 6.5 is built against the OpenSAML 4
line. Moving to OpenSAML 5 requires upgrading Spring Security itself (which cascades to the Spring Boot
version), and the 4→5 jump is a breaking change to the SAML/XML/crypto APIs (`net.shibboleth.utilities:java-support`
is repackaged, `InitializationService`/XMLObject APIs change, xmlsec major bump).

**Why not rushed:** this is a security-critical XML-signature stack. A hurried major upgrade risks breaking
the assertion signature validation that pentesting confirmed is currently solid (no forgery / XSW / XXE),
which would be a worse outcome than the EOL exposure. It must be done as a scoped Spring Boot / Spring
Security upgrade with full SAML round-trip testing (IdP-issue + SP/broker-consume, both bindings).

**Mitigation until then:** the SAML XML parser is XXE/DTD-hardened and entity-expansion-bounded, signature
validation reads only from the signed element, and assertion conditions/issuer/recipient/status are now
enforced (SAML-1/S-H1/S-H2/SAML-3 fixed). Track upstream OpenSAML 4.x advisories.

## Testing coverage gaps (not code defects — need more pentest depth)
- **XSW2–XSW8**: only XSW1 was scripted live (and rejected). The deeper signature-wrapping variants should be
  exercised in a follow-up pentest run.
- **eID EncryptedID decryption** and the **live DigiD ArtifactResolve mTLS SOAP back-channel** were not
  exercised (no live DigiD test peer). Cover when an eID test environment is available.
- **`/broker/{alias}/callback` end-to-end HTTP round-trip + RelayState gate**: the SAML pentest validated the
  assertion validator directly (stronger) but not the full browser round-trip; worth an integration test.

## Follow-up hardening (lower priority)
- **InResponseTo binding**: the inbound SAML broker does not persist outbound AuthnRequest ids, so
  `InResponseTo` is validated when present but not required (keeps IdP-initiated SSO working). Bind it once
  outbound request-ids are tracked (see `OpenSamlAssertionValidator` TODO).
- **L5**: legacy AES/ECB decrypt fallback retained for existing-row compatibility (now logged).
- **L6**: generated bootstrap admin password is logged (zero-config trade-off; set `HELIX_ADMIN_PASSWORD`).
