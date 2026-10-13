/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

/**
 * Helix IAM SSO P6: OIDC Back-Channel Logout fan-out — for each client in the terminated SSO session that
 * registered a {@code backchannel_logout_uri}, mints a signed {@code logout_token} ({@link LogoutTokenIssuer})
 * and POSTs it form-encoded. Best-effort: an unreachable / failing RP never blocks the others or the logout.
 */
@Component
public class BackchannelLogoutNotifier {

    private static final Logger LOG = LogManager.getLogger(BackchannelLogoutNotifier.class);

    /** A client in the session and where to notify it. */
    public record Target(String clientId, String backchannelLogoutUri) {
    }

    /** Seam over the HTTP POST so the fan-out logic is unit-testable without a server. */
    public interface Poster {
        void post(String uri, String logoutToken);
    }

    private final LogoutTokenIssuer issuer;
    private final Poster poster;

    /**
     * Production wiring: the egress-guarded HTTP poster, unless a {@link Poster} bean is present (the e2e suite
     * registers one that records the logout tokens instead of sending them).
     */
    @org.springframework.beans.factory.annotation.Autowired
    public BackchannelLogoutNotifier(final LogoutTokenIssuer issuer, final OutboundUrlGuard egressGuard,
                                     final org.springframework.beans.factory.ObjectProvider<Poster> posterOverride) {
        this(issuer, posterOverride.getIfAvailable(() -> new HttpPoster(egressGuard)));
    }

    BackchannelLogoutNotifier(final LogoutTokenIssuer issuer, final Poster poster) {
        this.issuer = issuer;
        this.poster = poster;
    }

    /**
     * POST a fresh logout_token to every target that has a back-channel URI, signed with {@code realm}'s key
     * (the realm of the terminated session) and carrying {@code issuerUrl} (that realm's issuer).
     */
    public void notifyClients(final String realm, final String issuerUrl, final String subject, final String sid,
                              final List<Target> targets) {
        if (targets == null) {
            return;
        }
        for (final Target target : targets) {
            if (target.backchannelLogoutUri() == null || target.backchannelLogoutUri().isBlank()) {
                continue;
            }
            try {
                final String logoutToken = issuer.issue(realm, issuerUrl, target.clientId(), subject, sid);
                poster.post(target.backchannelLogoutUri(), logoutToken);
                LOG.info("Back-channel logout sent to {} ({})", target.clientId(), target.backchannelLogoutUri());
            } catch (final RuntimeException e) {
                LOG.warn("Back-channel logout to {} failed (continuing): {}", target.clientId(), e.getMessage());
            }
        }
    }

    /** Default form-POST {@code logout_token=<jwt>} with a short timeout. */
    static final class HttpPoster implements Poster {
        /** 3 s connect, 5 s in total; the answer's body is not used (read up to 64 KB). */
        private static final PinnedHttpFetcher.Limits LIMITS = new PinnedHttpFetcher.Limits(Duration.ofSeconds(3),
                Duration.ofSeconds(5), 64 * 1024);
        private final PinnedHttpFetcher http;

        HttpPoster(final OutboundUrlGuard egressGuard) {
            this.http = PinnedHttpFetcher.plain(egressGuard);
        }

        @Override
        public void post(final String uri, final String logoutToken) {
            // M6: the back-channel logout URI comes from (self-service) client registration: pinned to the validated
            // address, no redirects
            final String body = "logout_token=" + java.net.URLEncoder.encode(logoutToken, StandardCharsets.UTF_8);
            try {
                http.post(uri, java.util.Map.of("Content-Type", "application/x-www-form-urlencoded"),
                        body.getBytes(StandardCharsets.UTF_8), LIMITS);
            } catch (final PinnedHttpFetcher.FetchException e) {
                if (e.kind() != PinnedHttpFetcher.FetchException.Kind.TOO_LARGE) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            } catch (final IllegalArgumentException e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }
}
