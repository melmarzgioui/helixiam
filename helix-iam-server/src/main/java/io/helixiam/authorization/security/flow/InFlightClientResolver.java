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
     * Item A8: the URL of the pending {@code /oauth2/authorize} request saved in the session (not consumed), to send
     * the user back into their sign-in after registering or verifying their email. Empty when none is pending.
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
            final String path = java.net.URI.create(saved.getRedirectUrl()).getPath();
            return path != null && path.endsWith("/oauth2/authorize") && "GET".equalsIgnoreCase(saved.getMethod())
                    ? java.util.Optional.of(saved.getRedirectUrl()) : java.util.Optional.empty();
        } catch (final IllegalArgumentException e) {
            return java.util.Optional.empty();
        }
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
