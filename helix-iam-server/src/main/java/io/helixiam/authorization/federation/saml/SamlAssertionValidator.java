/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;

import java.util.Map;

/**
 * Helix IAM E5.2: validates a SAML2 {@code <Response>} (signature, conditions, audience, subject
 * confirmation, replay) and returns the verified assertion. Behind a seam so {@link Saml2IdentityProvider}'s
 * AuthnRequest building + attribute→identity mapping are unit-testable; the production impl is backed
 * by OpenSAML (via {@code spring-security-saml2-service-provider}) and is validated against a live IdP.
 */
public interface SamlAssertionValidator {

    /**
     * @param config             the provider config (issuer, audience, IdP signing cert)
     * @param samlResponseBase64 the base64 SAMLResponse from the ACS POST
     * @param expectedRelayState the RelayState the runtime stashed at {@code start} (CSRF binding)
     * @return the validated assertion (NameID + attributes)
     * @throws IllegalStateException if the response fails any validation check
     */
    ValidatedAssertion validate(SamlProviderConfig config, String samlResponseBase64, String expectedRelayState);

    /** A validated SAML assertion: the subject NameID and the asserted attributes. */
    record ValidatedAssertion(String nameId, Map<String, String> attributes) {
    }
}
