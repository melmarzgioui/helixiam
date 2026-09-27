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

/**
 * Helix IAM (named flows): resolves the in-flight relying party for a login. When an unauthenticated user
 * hits {@code /oauth2/authorize}, Spring Security caches that request and bounces them to {@code /login};
 * the cached request still carries the {@code client_id} query parameter. Reading it at flow-resolution
 * time lets login run the flow bound to <em>that</em> client (per-client flow override), falling back to
 * the realm default when there is no in-flight client (e.g. direct {@code /login}).
 *
 * <p>Reads the cache without consuming it — the OAuth round-trip still needs the saved request afterwards.
 */
public final class InFlightClientResolver {

    private static final RequestCache REQUEST_CACHE = new HttpSessionRequestCache();
    private static final String CLIENT_ID_PARAM = "client_id";

    private InFlightClientResolver() {
    }

    /** The {@code client_id} of the cached authorize request, or {@code null} if there is none. */
    public static String clientId(final HttpServletRequest request, final HttpServletResponse response) {
        return clientIdOf(REQUEST_CACHE.getRequest(request, response));
    }

    /**
     * Item A8: the pending {@code /oauth2/authorize} request saved in the session (not consumed), as a path and query on
     * this server, to send the user back into their sign-in after registering or verifying their email. Empty when none
     * is pending.
     */
    public static java.util.Optional<String> pendingAuthorizeUrl(final HttpServletRequest request) {
        if (request == null || request.getSession(false) == null) {
            return java.util.Optional.empty();
        }
        final SavedRequest saved = REQUEST_CACHE.getRequest(request, null);
        if (saved == null || saved.getRedirectUrl() == null) {
            return java.util.Optional.empty();
        }
        try {
            final java.net.URI uri = java.net.URI.create(saved.getRedirectUrl());
            final String path = uri.getRawPath();
            // CodeQL #255: only the path and query go out, never the saved URL's scheme and host, so the redirect stays
            // on this server; a path that a browser would read as another host ("//host/...") is refused.
            if (path == null || !path.startsWith("/") || path.startsWith("//") || !path.endsWith("/oauth2/authorize")
                    || !"GET".equalsIgnoreCase(saved.getMethod())) {
                return java.util.Optional.empty();
            }
            return java.util.Optional.of(uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery());
        } catch (final IllegalArgumentException e) {
            return java.util.Optional.empty();
        }
    }

    /**
     * The single value of {@code name} on the pending {@code /oauth2/authorize} request saved in the session (not
     * consumed), e.g. {@code login_hint} (item E3). Empty when none is pending or the parameter is absent / repeated.
     */
    public static java.util.Optional<String> pendingAuthorizeParameter(final HttpServletRequest request, final String name) {
        if (pendingAuthorizeUrl(request).isEmpty()) {
            return java.util.Optional.empty();
        }
        final String[] values = REQUEST_CACHE.getRequest(request, null).getParameterValues(name);
        return values != null && values.length == 1 ? java.util.Optional.ofNullable(values[0]) : java.util.Optional.empty();
    }

    /** Extracts {@code client_id} from a saved request (package-visible for testing). */
    static String clientIdOf(final SavedRequest saved) {
        if (saved == null) {
            return null;
        }
        final String[] values = saved.getParameterValues(CLIENT_ID_PARAM);
        return values != null && values.length > 0 ? values[0] : null;
    }
}
