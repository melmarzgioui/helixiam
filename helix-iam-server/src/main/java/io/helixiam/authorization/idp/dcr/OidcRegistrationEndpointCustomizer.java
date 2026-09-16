/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.dcr;

import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;

import java.util.function.Consumer;

/**
 * Helix IAM E11 (RFC 7591): advertises the realm's Dynamic Client Registration endpoint in the OIDC
 * discovery document. Wired into SAS via {@code oidc().providerConfigurationEndpoint(...
 * .providerConfigurationCustomizer(...))}. The {@code issuer} claim SAS already populated is the
 * realm-prefixed {@code {base}/realms/{realm}}; the DCR endpoint is served under the same prefix, so
 * {@code registration_endpoint = {issuer}/connect/register}. Additive — never touches the token hot path.
 */
public final class OidcRegistrationEndpointCustomizer implements Consumer<OidcProviderConfiguration.Builder> {

    @Override
    public void accept(final OidcProviderConfiguration.Builder builder) {
        builder.claims(claims -> {
            final Object issuer = claims.get("issuer");
            if (issuer != null) {
                claims.put("registration_endpoint", issuer + "/connect/register");
            }
        });
    }
}
