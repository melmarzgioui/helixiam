/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;


/**
 * Helix IAM E5.2: fail-closed default {@link SamlAssertionValidator}. SAML Response validation
 * (signature, conditions, audience, replay) is done by the OpenSAML-backed
 * {@link OpenSamlAssertionValidator}. Wherever that bean is not present this default REJECTS every assertion,
 * so the SAML broker fails closed rather than ever trusting an unvalidated response.
 */
public class UnconfiguredSamlAssertionValidator implements SamlAssertionValidator {

    @Override
    public ValidatedAssertion validate(final SamlProviderConfig config, final String samlResponseBase64,
                                       final String expectedRelayState, final String expectedRequestId) {
        throw new IllegalStateException("SAML assertion validation is not configured for provider "
                + config.alias() + " — install the OpenSAML-backed SamlAssertionValidator (E5.2 follow-up)");
    }
}
