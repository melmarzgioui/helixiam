/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.requiredactions;

import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.emailverification.EmailVerificationService;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * C3: "no tokens until the email address is verified". Runs inside the token customizer, so it holds for every
 * grant that issues a token for a user (authorization code after any kind of sign-in, refresh, token exchange): when
 * {@link EmailVerificationService#pending} says the user still has to verify (the realm requires it, or the user has
 * the {@code VERIFY_EMAIL} required action), the token request fails with {@code access_denied}. The interactive
 * password sign-in is held earlier by {@link RequiredActionsGate}, which sends the link and waits for it.
 */
public final class EmailVerificationTokenGuard {

    private static final Logger LOG = LogManager.getLogger(EmailVerificationTokenGuard.class);

    private EmailVerificationTokenGuard() {
    }

    public static void check(final JwtEncodingContext context, final EmailVerificationService verification) {
        if (verification == null || context.getPrincipal() == null
                || AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
            return; // machine tokens have no user
        }
        final String realm = RealmContextHolder.get();
        final String userId = context.getPrincipal().getName();
        if (verification.pending(realm, userId)) {
            LOG.info("Token refused for user {} in realm {}: email address not verified",
                    LogSafe.sanitize(userId), LogSafe.sanitize(realm));
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,
                    "The user's email address is not verified.", null));
        }
    }
}
