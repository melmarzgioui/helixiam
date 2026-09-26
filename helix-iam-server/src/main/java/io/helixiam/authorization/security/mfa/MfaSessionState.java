/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 1.0 item 6: records in the HTTP session that the signed-in user passed the second factor (TOTP or a recovery
 * code, or an allowed enrolment skip) during THIS sign-in. Cleared on every password login, so each sign-in has
 * to present a factor again. Read by {@link MfaEnforcementFilter} before an authorization code is issued.
 */
public final class MfaSessionState {

    static final String ATTRIBUTE = "HELIX_MFA_VERIFIED_USER";

    private MfaSessionState() {
    }

    public static void markVerified(final HttpServletRequest request, final String userId) {
        request.getSession(true).setAttribute(ATTRIBUTE, userId);
    }

    /** Marks the current request's session (for verifiers that have no request parameter). */
    public static void markVerified(final String userId) {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            markVerified(attrs.getRequest(), userId);
        }
    }

    public static boolean isVerified(final HttpServletRequest request, final String userId) {
        final HttpSession session = request.getSession(false);
        return session != null && userId != null && userId.equals(session.getAttribute(ATTRIBUTE));
    }

    public static void clear(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(ATTRIBUTE);
        }
    }
}
