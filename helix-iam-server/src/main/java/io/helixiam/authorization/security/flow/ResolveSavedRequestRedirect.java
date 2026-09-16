/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

/**
 * Helix IAM SSO P1: resumes the relying party's original {@code /oauth2/authorize} request after login.
 *
 * <p>When an unauthenticated user hits {@code /oauth2/authorize}, Spring Security caches that request and
 * bounces them to {@code /login}. Every login completion path historically redirected to a fixed
 * {@code spBaseUrl} (the dashboard's own client), so the authorization code came back for the dashboard
 * rather than the client that started the flow — breaking cross-app SSO. This helper consumes the cached
 * request and resumes it, so login hands control back to the originating client.
 *
 * <p>The cached {@link SavedRequest#getRedirectUrl()} already carries the full realm-prefixed URL
 * (e.g. {@code /realms/{realm}/oauth2/authorize?...}), so it is returned verbatim — never re-prefixed.
 * Falls back to the supplied default only when there is no saved request (e.g. a direct visit to
 * {@code /login}). Reads the same session-backed cache that {@link InFlightClientResolver} reads, and is
 * the single consumer ({@code removeRequest}).
 */
public final class ResolveSavedRequestRedirect {

    private final RequestCache cache;

    public ResolveSavedRequestRedirect() {
        this(new HttpSessionRequestCache());
    }

    /** Package-visible for tests — inject a mock {@link RequestCache}. */
    ResolveSavedRequestRedirect(final RequestCache cache) {
        this.cache = cache;
    }

    /**
     * The saved {@code /oauth2/authorize} URL to resume (consuming it from the cache), or {@code fallback}
     * when there is none. The returned URL is already realm-prefixed and must not be modified.
     */
    public String resumeUrlOrDefault(final HttpServletRequest request, final HttpServletResponse response,
                                     final String fallback) {
        final SavedRequest saved = cache.getRequest(request, response);
        if (saved == null) {
            return fallback;
        }
        cache.removeRequest(request, response);
        return saved.getRedirectUrl();
    }

    /** Servlet-handler form: redirect the response to the resumed URL (or the fallback). */
    public void sendRedirect(final HttpServletRequest request, final HttpServletResponse response,
                             final String fallback) throws IOException {
        response.sendRedirect(resumeUrlOrDefault(request, response, fallback));
    }

    /** {@code @Controller} form: a Spring MVC {@code "redirect:"} view string to the resumed URL. */
    public String redirectView(final HttpServletRequest request, final HttpServletResponse response,
                               final String fallback) {
        return "redirect:" + resumeUrlOrDefault(request, response, fallback);
    }
}
