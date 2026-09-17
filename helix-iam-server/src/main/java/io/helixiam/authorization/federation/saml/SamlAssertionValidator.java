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
     * @param expectedRequestId  the outbound AuthnRequest id the broker minted + persisted server-side
     *                           for this session (SAML-1/S-H1). When non-null the flow is solicited
     *                           (SP-initiated): the assertion's {@code InResponseTo} is REQUIRED and MUST
     *                           equal this id (the broker consumes the id per callback, so it is
     *                           single-use / replay-proof). When null there is no pending request — an
     *                           unsolicited (IdP-initiated) assertion, accepted only when the config
     *                           permits it.
     * @return the validated assertion (NameID + attributes)
     * @throws IllegalStateException if the response fails any validation check
     */
    ValidatedAssertion validate(SamlProviderConfig config, String samlResponseBase64, String expectedRelayState,
                                String expectedRequestId);

    /**
     * Convenience overload for callers with no pending outbound request id (unsolicited / IdP-initiated,
     * or a test seam). Equivalent to {@link #validate(SamlProviderConfig, String, String, String)} with a
     * {@code null} {@code expectedRequestId}.
     */
    default ValidatedAssertion validate(final SamlProviderConfig config, final String samlResponseBase64,
                                        final String expectedRelayState) {
        return validate(config, samlResponseBase64, expectedRelayState, null);
    }

    /** A validated SAML assertion: the subject NameID and the asserted attributes. */
    record ValidatedAssertion(String nameId, Map<String, String> attributes) {
    }
}
