/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.util.Optional;

/**
 * One-time values for the next rendering of the login page, kept in the HTTP session (never in the URL, so a
 * username does not end up in logs, history or a {@code Referer}): the username to pre-fill (after a failed sign-in,
 * or the address just verified) and a notice ({@code verified}). Read once, then gone.
 */
public final class LoginFlash {

    static final String USERNAME = "HELIX_LOGIN_FLASH_USERNAME";
    static final String NOTICE = "HELIX_LOGIN_FLASH_NOTICE";
    /** The only notice there is: the email address was just verified. */
    public static final String VERIFIED = "verified";
    /** Longer values are not kept (a username is at most this long). */
    static final int MAX_USERNAME = 256;

    private LoginFlash() {
    }

    /** Pre-fills {@code username} on the next login page (ignored when blank or too long). */
    public static void username(final HttpServletRequest request, final String username) {
        if (request == null || username == null || username.isBlank() || username.length() > MAX_USERNAME) {
            return;
        }
        request.getSession(true).setAttribute(USERNAME, username.strip());
    }

    /** Shows {@code notice} on the next login page. */
    public static void notice(final HttpServletRequest request, final String notice) {
        if (request != null && VERIFIED.equals(notice)) {
            request.getSession(true).setAttribute(NOTICE, notice);
        }
    }

    public static Optional<String> takeUsername(final HttpServletRequest request) {
        return take(request, USERNAME);
    }

    public static Optional<String> takeNotice(final HttpServletRequest request) {
        return take(request, NOTICE);
    }

    private static Optional<String> take(final HttpServletRequest request, final String attribute) {
        final HttpSession session = request == null ? null : request.getSession(false);
        if (session == null || !(session.getAttribute(attribute) instanceof String value)) {
            return Optional.empty();
        }
        session.removeAttribute(attribute);
        return Optional.of(value);
    }
}
