/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Helix IAM SSO P9: the seam a federation broker uses to reach an upstream IdP's logout endpoint (the OIDC
 * {@code end_session_endpoint}, or a SAML SLO service). Best-effort and unit-testable without a network: a
 * test supplies a capturing implementation; production uses {@link Http}.
 */
public interface UpstreamLogoutClient {

    /** Best-effort GET of an upstream logout URL (OIDC RP-initiated {@code end_session}). */
    void get(String url);

    /** Default GET with a short timeout; failures are swallowed so logout never blocks. */
    class Http implements UpstreamLogoutClient {
        private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

        @Override
        public void get(final String url) {
            try {
                final HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(5)).GET().build();
                httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            } catch (final Exception e) {
                throw new RuntimeException("Upstream logout GET failed: " + e.getMessage(), e);
            }
        }
    }
}
