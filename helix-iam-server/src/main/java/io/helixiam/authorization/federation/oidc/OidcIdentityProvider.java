/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.oidc;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Helix IAM E5.2: the OIDC federation broker (authorization-code flow). {@link #start} builds the
 * authorize redirect with a fresh nonce + the runtime's anti-forgery state; {@link #callback}
 * verifies the returned state (CSRF), exchanges the code via {@link OidcTokenClient} (back-channel
 * TLS), verifies the ID-token nonce (replay), and maps the claims to a {@link BrokeredIdentity}.
 * Social providers (Google/Microsoft/GitHub) are this broker with preset {@link OidcProviderConfig}s.
 */
public class OidcIdentityProvider implements IdentityProvider {

    private static final String SUB = "sub";
    private static final String EMAIL = "email";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String NONCE = "nonce";

    private final OidcProviderConfig config;
    private final OidcTokenClient tokenClient;
    private final Supplier<String> nonceGenerator;
    private final io.helixiam.authorization.federation.UpstreamLogoutClient upstreamLogoutClient;

    public OidcIdentityProvider(final OidcProviderConfig config, final OidcTokenClient tokenClient,
                                final Supplier<String> nonceGenerator) {
        this(config, tokenClient, nonceGenerator, new io.helixiam.authorization.federation.UpstreamLogoutClient.Http());
    }

    public OidcIdentityProvider(final OidcProviderConfig config, final OidcTokenClient tokenClient,
                                final Supplier<String> nonceGenerator,
                                final io.helixiam.authorization.federation.UpstreamLogoutClient upstreamLogoutClient) {
        this.config = config;
        this.tokenClient = tokenClient;
        this.nonceGenerator = nonceGenerator;
        this.upstreamLogoutClient = upstreamLogoutClient;
    }

    @Override
    public IdpMetadata metadata() {
        return IdpMetadata.of(config.alias(), IdpMetadata.Protocol.OIDC, config.displayName());
    }

    @Override
    public RedirectResponse start(final AuthnRequestContext context) {
        final String nonce = nonceGenerator.get();
        final String location = config.authorizationEndpoint() + "?"
                + "response_type=code"
                + "&client_id=" + enc(config.clientId())
                + "&redirect_uri=" + enc(context.callbackUri())
                + "&scope=" + enc(config.scopeParam())
                + "&state=" + enc(context.state())
                + "&nonce=" + enc(nonce);
        return new RedirectResponse(location, Map.of(NONCE, nonce));
    }

    @Override
    public BrokeredIdentity callback(final CallbackContext context) {
        final Map<String, String> params = context.parameters();
        final String returnedState = params.get("state");
        if (context.expectedState() == null || !context.expectedState().equals(returnedState)) {
            throw new IllegalStateException("OIDC state mismatch (possible CSRF) for provider " + config.alias());
        }
        final String code = params.get("code");
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("OIDC callback missing authorization code for provider " + config.alias());
        }

        final OidcTokenClient.OidcTokens tokens = tokenClient.exchange(config, code, context.redirectUri());
        final Map<String, Object> claims = tokens.idTokenClaims();

        if (context.expectedNonce() != null && !context.expectedNonce().equals(str(claims.get(NONCE)))) {
            throw new IllegalStateException("OIDC nonce mismatch (possible replay) for provider " + config.alias());
        }

        final String subject = str(claims.get(SUB));
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("OIDC ID token has no subject for provider " + config.alias());
        }
        final String email = str(claims.get(EMAIL));
        final boolean emailVerified = Boolean.TRUE.equals(claims.get(EMAIL_VERIFIED))
                || "true".equalsIgnoreCase(str(claims.get(EMAIL_VERIFIED)));

        final Map<String, String> attributes = new HashMap<>();
        claims.forEach((key, value) -> {
            if (value != null && !SUB.equals(key) && !NONCE.equals(key)) {
                attributes.put(key, value.toString());
            }
        });
        return new BrokeredIdentity(config.alias(), subject, email, emailVerified, attributes);
    }

    @Override
    public void logout(final LogoutContext context) {
        // SSO P9: RP-initiated logout at the upstream OIDC IdP. Best-effort — a failure must never block the
        // local Helix logout, so all errors are swallowed.
        final String endSession = config.endSessionEndpoint();
        if (endSession == null || endSession.isBlank()) {
            return; // this provider advertises no end_session_endpoint
        }
        final StringBuilder url = new StringBuilder(endSession)
                .append(endSession.contains("?") ? "&" : "?")
                .append("client_id=").append(enc(config.clientId()));
        if (context.upstreamIdToken() != null && !context.upstreamIdToken().isBlank()) {
            url.append("&id_token_hint=").append(enc(context.upstreamIdToken()));
        }
        try {
            upstreamLogoutClient.get(url.toString());
        } catch (final RuntimeException e) {
            // upstream IdP unreachable / rejected the logout — the local session is already gone.
        }
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }

    private static String str(final Object value) {
        return value == null ? null : value.toString();
    }
}
