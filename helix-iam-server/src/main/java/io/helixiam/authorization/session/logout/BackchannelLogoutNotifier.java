/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session.logout;

import io.helixiam.common.net.OutboundUrlGuard;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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

    @org.springframework.beans.factory.annotation.Autowired
    public BackchannelLogoutNotifier(final LogoutTokenIssuer issuer, final OutboundUrlGuard egressGuard) {
        this(issuer, new HttpPoster(egressGuard));
    }

    BackchannelLogoutNotifier(final LogoutTokenIssuer issuer, final Poster poster) {
        this.issuer = issuer;
        this.poster = poster;
    }

    /** POST a fresh logout_token to every target that has a back-channel URI. */
    public void notifyClients(final String issuerUrl, final String subject, final String sid, final List<Target> targets) {
        if (targets == null) {
            return;
        }
        for (final Target target : targets) {
            if (target.backchannelLogoutUri() == null || target.backchannelLogoutUri().isBlank()) {
                continue;
            }
            try {
                final String logoutToken = issuer.issue(issuerUrl, target.clientId(), subject, sid);
                poster.post(target.backchannelLogoutUri(), logoutToken);
                LOG.info("Back-channel logout sent to {} ({})", target.clientId(), target.backchannelLogoutUri());
            } catch (final RuntimeException e) {
                LOG.warn("Back-channel logout to {} failed (continuing): {}", target.clientId(), e.getMessage());
            }
        }
    }

    /** Default form-POST {@code logout_token=<jwt>} with a short timeout. */
    static final class HttpPoster implements Poster {
        private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
        private final OutboundUrlGuard egressGuard;

        HttpPoster(final OutboundUrlGuard egressGuard) {
            this.egressGuard = egressGuard;
        }

        @Override
        public void post(final String uri, final String logoutToken) {
            egressGuard.checkAllowed(uri); // M6: back-channel logout URI comes from (self-service) client registration
            final String body = "logout_token=" + java.net.URLEncoder.encode(logoutToken, StandardCharsets.UTF_8);
            final HttpRequest request = HttpRequest.newBuilder(URI.create(uri))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            try {
                httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            } catch (final Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }
        }
    }
}
