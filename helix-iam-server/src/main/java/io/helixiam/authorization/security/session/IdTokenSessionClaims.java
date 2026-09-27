/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * A3: stamps {@code sid} and {@code auth_time} into an ID token from the authorization's SSO-session binding
 * ({@link SsoSessionBindingAuthorizationService}). The binding is made once, when the code is issued, and kept
 * on the authorization, so the code exchange and every refresh carry the same {@code sid} and the time of the
 * last interactive authentication (never the time of the token request). {@code auth_time} is emitted as epoch
 * seconds (a JSON number, as OIDC Core requires).
 */
public final class IdTokenSessionClaims {

    public static final String SID = "sid";
    public static final String AUTH_TIME = "auth_time";

    private IdTokenSessionClaims() {
    }

    /** Adds the session claims to an {@code id_token}; any other token type is left untouched. */
    public static void apply(final JwtEncodingContext context) {
        if (context.getTokenType() == null || !"id_token".equals(context.getTokenType().getValue())) {
            return;
        }
        final OAuth2Authorization authorization = context.getAuthorization();
        if (authorization == null) {
            return;
        }
        final Object sid = authorization.getAttribute(SsoSessionBindingAuthorizationService.SID_ATTRIBUTE);
        final Object authTime = authorization.getAttribute(SsoSessionBindingAuthorizationService.AUTH_TIME_ATTRIBUTE);
        context.getClaims().claims(claims -> {
            if (sid instanceof String value && !value.isBlank()) {
                claims.put(SID, value);
            }
            if (authTime instanceof Long seconds) {
                claims.put(AUTH_TIME, seconds);
            }
        });
    }
}
