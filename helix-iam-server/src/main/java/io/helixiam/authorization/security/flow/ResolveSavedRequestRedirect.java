/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.security.realm.RealmContextHolder;
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
 * When there is no saved request (e.g. a direct visit to {@code /login}), a realm's user goes to the realm's account
 * console and a master-realm operator to the supplied default (the admin console), see {@link #landing}. Reads the same session-backed cache that {@link InFlightClientResolver} reads, and is
 * the single consumer ({@code removeRequest}).
 */
public final class ResolveSavedRequestRedirect {

    private static final String MASTER = "master";

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
            return landing(request, fallback);
        }
        cache.removeRequest(request, response);
        return saved.getRedirectUrl();
    }

    /**
     * Where a sign-in that no application is waiting for ends: in a realm other than master, the realm's account
     * console ({@code /realms/{realm}/account}) — its users are end users, and {@code fallback} (the admin console at
     * {@code sp.base.url}, another origin) is neither theirs nor allowed by the sign-in pages' CSP {@code form-action}.
     * In master (operators) or outside a realm, {@code fallback}.
     */
    static String landing(final HttpServletRequest request, final String fallback) {
        final String realm = RealmContextHolder.get();
        if (realm == null || MASTER.equals(realm)) {
            return fallback;
        }
        // Absolute (on this request's scheme and host, forwarded headers honoured), like a saved request's URL: a
        // "redirect:" view would prefix a path with the realm's context path a second time.
        return org.springframework.web.servlet.support.ServletUriComponentsBuilder.fromContextPath(request)
                .path("/account").replaceQuery(null).build().toUriString();
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
