/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;

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
        /** 3 s connect, 5 s in total; the answer's body is not used (read up to 64 KB). */
        private static final PinnedHttpFetcher.Limits LIMITS = new PinnedHttpFetcher.Limits(Duration.ofSeconds(3),
                Duration.ofSeconds(5), 64 * 1024);
        private final PinnedHttpFetcher http;

        /** Secure default (block-private); reads {@code HELIX_EGRESS_ALLOW_PRIVATE} for the dev escape hatch. */
        public Http() {
            this(new OutboundUrlGuard());
        }

        public Http(final OutboundUrlGuard egressGuard) {
            this.http = PinnedHttpFetcher.plain(egressGuard);
        }

        @Override
        public void get(final String url) {
            // M6: the upstream logout URL comes from admin IdP config: pinned to the validated address, no redirects
            try {
                http.get(url, java.util.Map.of(), LIMITS);
            } catch (final PinnedHttpFetcher.FetchException e) {
                if (e.kind() != PinnedHttpFetcher.FetchException.Kind.TOO_LARGE) {
                    throw new RuntimeException("Upstream logout GET failed: " + e.getMessage(), e);
                }
            } catch (final IllegalArgumentException e) {
                throw new RuntimeException("Upstream logout GET failed: " + e.getMessage(), e);
            }
        }
    }
}
