package io.helixiam.authorization.federation.eid;

/**
 * Helix IAM E6: validates an eID SAML {@code <Response>} — decrypts the EncryptedAssertion with the
 * SP key, verifies the IdP signature, checks issuer/audience/time-window/replay, enforces the minimum
 * level of assurance, and returns the subject id + LoA + attributes. Behind a seam so the eID
 * connector's request building + identity mapping stay unit-testable; the production impl is backed
 * by OpenSAML.
 */
public interface EidAssertionValidator {

    /**
     * @param config             the eID provider config
     * @param samlResponseBase64 the base64 SAMLResponse from the ACS POST
     * @param expectedRelayState the RelayState the runtime stashed at {@code start} (CSRF binding)
     * @return the validated, decrypted assertion
     * @throws IllegalStateException if any check fails (signature, decryption, audience, LoA, replay)
     */
    EidAssertion validate(EidProviderConfig config, String samlResponseBase64, String expectedRelayState);
}
