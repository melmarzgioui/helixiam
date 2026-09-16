/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.device;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.time.Instant;
import java.util.Base64;

/**
 * Story 1 (CLI browser login): a drop-in replacement for Spring Authorization Server's
 * {@code OAuth2RefreshTokenGenerator} whose public-client guard is relaxed for NATIVE apps.
 *
 * <p>SAS refuses to issue a refresh token to a public client (auth method {@code none}) on the
 * {@code authorization_code} grant — a safe default for browser SPAs. But a CLI is a native app (RFC 8252),
 * which may safely hold a rotating refresh token so the user stays signed in. We treat a client as native when
 * it is registered for the device grant ({@code urn:ietf:params:oauth:grant-type:device_code}) — CLIs are, SPAs
 * are not. For native apps we issue the refresh token; for everything else the SAS behaviour is preserved
 * exactly. Rotation (SAS default, {@code reuseRefreshTokens=false}) keeps this OAuth 2.1-safe.
 */
public final class NativeAppRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

    private static final AuthorizationGrantType DEVICE_CODE =
            new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code");

    private final StringKeyGenerator refreshTokenGenerator =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Override
    public OAuth2RefreshToken generate(final OAuth2TokenContext context) {
        if (context.getTokenType() == null
                || !OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        if (isPublicClientForAuthorizationCodeGrant(context) && !isNativeApp(context)) {
            // SAS guard preserved for non-native public clients (browser SPAs).
            return null;
        }
        final Instant issuedAt = Instant.now();
        final Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
    }

    /** Mirrors SAS's private guard: a public client (method NONE) using the authorization_code grant. */
    private static boolean isPublicClientForAuthorizationCodeGrant(final OAuth2TokenContext context) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType())
                && (context.getAuthorizationGrant() != null
                && context.getAuthorizationGrant().getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal)) {
            return ClientAuthenticationMethod.NONE.equals(clientPrincipal.getClientAuthenticationMethod());
        }
        return false;
    }

    /** A native app (RFC 8252) — approximated by registration for the device authorization grant. */
    private static boolean isNativeApp(final OAuth2TokenContext context) {
        return context.getRegisteredClient().getAuthorizationGrantTypes().contains(DEVICE_CODE);
    }
}
