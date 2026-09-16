/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.spi;

import java.util.Map;

/**
 * Helix IAM E5.1: the Identity Federation SPI. A pluggable broker connector for one external IdP
 * (OIDC / SAML2-SP / LDAP / social / EU eID). Auto-discovered like the other Helix SPIs: drop a
 * {@code @Component} implementing this and {@link io.helixiam.authorization.federation.IdentityProviderRegistry}
 * routes to it by {@link IdpMetadata#alias()}. The concrete protocol brokers land in E5.2.
 */
public interface IdentityProvider {

    /** Protocol + alias + display name; the registry keys providers by the alias. */
    IdpMetadata metadata();

    /** Build the redirect that starts authentication at the external IdP (authorize / AuthnRequest). */
    RedirectResponse start(AuthnRequestContext context);

    /** Validate the IdP's response and normalize it into a {@link BrokeredIdentity}. */
    BrokeredIdentity callback(CallbackContext context);

    /** RP-initiated / single logout at the external IdP (no-op for protocols without SLO). */
    void logout(LogoutContext context);

    /** Context for {@link #start}: the realm, anti-forgery state, and where the IdP returns to. */
    record AuthnRequestContext(String realmId, String state, String callbackUri) {
    }

    /** How the browser is sent to the IdP: a 302 redirect, or an auto-submitting HTML POST form. */
    enum Binding { REDIRECT, POST }

    /**
     * Where/how to send the browser to start authentication. For {@link Binding#REDIRECT} (OIDC
     * authorize, SAML HTTP-Redirect) the runtime 302s to {@link #location}. For {@link Binding#POST}
     * (SAML HTTP-POST binding, as DigiD/eHerkenning require) the runtime renders an auto-submitting
     * form that POSTs {@link #formFields} (e.g. {@code SAMLRequest}, {@code RelayState}) to
     * {@link #location}. {@link #parameters} carries runtime hints (e.g. the OIDC nonce to stash).
     */
    record RedirectResponse(String location, Map<String, String> parameters, Binding binding,
                            Map<String, String> formFields) {

        /** A 302 redirect to {@code location} (OIDC authorize / SAML HTTP-Redirect). */
        public RedirectResponse(final String location, final Map<String, String> parameters) {
            this(location, parameters, Binding.REDIRECT, Map.of());
        }

        /** An auto-submitting HTML POST form to {@code destination} with the given hidden fields. */
        public static RedirectResponse postForm(final String destination, final Map<String, String> formFields) {
            return new RedirectResponse(destination, Map.of(), Binding.POST, formFields);
        }
    }

    /**
     * Context for {@link #callback}: the realm, the raw response parameters from the IdP, and the
     * anti-forgery values the runtime stashed at {@link #start} (restored from the user's session) so
     * the provider can reject CSRF (state mismatch) and replay (nonce mismatch).
     */
    record CallbackContext(String realmId, Map<String, String> parameters,
                           String expectedState, String expectedNonce, String redirectUri) {
    }

    /**
     * Context for {@link #logout}: the realm + local user, the broker alias the session came through, and the
     * upstream session handles captured at brokered login so the broker can terminate the session at the
     * external IdP — the OIDC {@code id_token} (for {@code id_token_hint}) and the SAML NameID + SessionIndex.
     */
    record LogoutContext(String realmId, String userId, String idpAlias,
                         String upstreamIdToken, String upstreamNameId, String upstreamSessionIndex) {

        /** A minimal context with no upstream handles — federated logout becomes a no-op. */
        public LogoutContext(final String realmId, final String userId) {
            this(realmId, userId, null, null, null, null);
        }
    }
}
