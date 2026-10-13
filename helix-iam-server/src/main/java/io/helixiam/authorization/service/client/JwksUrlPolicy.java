/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * The one rule for a client's {@code jwksUrl} (the key set a {@code private_key_jwt} client signs its assertions
 * with), shared by the admin API and realm import: blank is fine; otherwise an https URL with a host. Plain http is
 * accepted only for {@code localhost} / {@code 127.0.0.1} under the {@code dev} profile. The console form applies the
 * same rule ({@code helix-dashboard/src/pages/jwksUrl.ts}).
 */
public final class JwksUrlPolicy {

    public static final String NOT_A_URL = "The JWKS URL is not a valid URL.";
    public static final String NOT_HTTPS = "The JWKS URL must be an https URL.";

    /** Stable machine-readable codes for {@link #code}, so a client can map them to its own translated copy
     * instead of matching the (English-only) {@link #problem} message text. */
    public static final String CODE_NOT_A_URL = "notUrl";
    public static final String CODE_NOT_HTTPS = "notHttps";

    private JwksUrlPolicy() {
    }

    /** The field error for {@code jwksUrl}, or null when it is acceptable. */
    public static String problem(final String jwksUrl, final boolean dev) {
        final Problem p = classify(jwksUrl, dev);
        return p == null ? null : p.message();
    }

    /** The stable code for {@code jwksUrl}'s problem ({@link #CODE_NOT_A_URL} / {@link #CODE_NOT_HTTPS}), or null. */
    public static String code(final String jwksUrl, final boolean dev) {
        final Problem p = classify(jwksUrl, dev);
        return p == null ? null : p.code();
    }

    private record Problem(String code, String message) {
    }

    private static Problem classify(final String jwksUrl, final boolean dev) {
        if (jwksUrl == null || jwksUrl.isBlank()) {
            return null;
        }
        final URI uri;
        try {
            uri = new URI(jwksUrl.trim());
        } catch (final URISyntaxException e) {
            return new Problem(CODE_NOT_A_URL, NOT_A_URL);
        }
        if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null) {
            return null;
        }
        if (dev && "http".equalsIgnoreCase(uri.getScheme())
                && ("localhost".equalsIgnoreCase(uri.getHost()) || "127.0.0.1".equals(uri.getHost()))) {
            return null;
        }
        return new Problem(CODE_NOT_HTTPS, NOT_HTTPS);
    }
}
