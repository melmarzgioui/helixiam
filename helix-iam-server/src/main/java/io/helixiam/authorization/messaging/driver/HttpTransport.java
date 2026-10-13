/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

/**
 * Helix IAM notifications (N3): the HTTP seam every network-backed driver (Twilio, generic-HTTP SMS, HTTP
 * email API, FCM, APNs) posts through. A test supplies a capturing implementation; production uses
 * {@link Default}. Returns the HTTP status so a driver can detect a rejected send.
 */
public interface HttpTransport {

    /** POST {@code body} to {@code url} with {@code headers}; returns the HTTP status code. */
    int post(String url, Map<String, String> headers, String body);

    /** A status + response body (for callers that need the response, e.g. the FCM OAuth token exchange). */
    record Response(int status, String body) {
    }

    /**
     * POST and return both the status and the response body. Default delegates to {@link #post} (empty body)
     * so the lambda test doubles that only implement {@link #post} keep working; {@link Default} overrides it.
     */
    default Response postForResponse(final String url, final Map<String, String> headers, final String body) {
        return new Response(post(url, headers, body), "");
    }

    /**
     * The live transport. M6: every POST goes through {@link PinnedHttpFetcher}: the guard resolves the realm-configured
     * URL once, inside the 10 s deadline, and the connection goes to the address it validated (TLS checked against the
     * host name), without following redirects; a response body is read up to 1 MB. A URL the guard refuses throws
     * {@link io.helixiam.common.net.SsrfBlockedException} (callers map it to a configuration failure); any other
     * failure is a {@link RuntimeException} "HTTP send failed".
     */
    @Component
    class Default implements HttpTransport {
        static final PinnedHttpFetcher.Limits LIMITS = new PinnedHttpFetcher.Limits(Duration.ofSeconds(5),
                Duration.ofSeconds(10), 1024 * 1024);
        private final PinnedHttpFetcher http;

        public Default(final OutboundUrlGuard egressGuard) {
            this.http = PinnedHttpFetcher.plain(egressGuard);
        }

        @Override
        public int post(final String url, final Map<String, String> headers, final String body) {
            try {
                return send(url, headers, body, false).status();
            } catch (final PinnedHttpFetcher.FetchException e) {
                if (e.kind() == PinnedHttpFetcher.FetchException.Kind.TOO_LARGE && e.status() > 0) {
                    return e.status(); // only the status is wanted: an oversized body does not matter
                }
                throw new RuntimeException("HTTP send failed: " + e.getMessage(), e);
            }
        }

        @Override
        public Response postForResponse(final String url, final Map<String, String> headers, final String body) {
            try {
                final PinnedHttpFetcher.Response r = send(url, headers, body, true);
                return new Response(r.status(), r.bodyAsString());
            } catch (final PinnedHttpFetcher.FetchException e) {
                throw new RuntimeException("HTTP send failed: " + e.getMessage(), e);
            }
        }

        private PinnedHttpFetcher.Response send(final String url, final Map<String, String> headers,
                final String body, final boolean readBody) throws PinnedHttpFetcher.FetchException {
            // M6: some notification driver endpoints (HTTP SMS/email) are realm-config'd: pinned, no redirects
            try {
                return http.exchange(new PinnedHttpFetcher.Request("POST", url, headers == null ? Map.of() : headers,
                        (body == null ? "" : body).getBytes(StandardCharsets.UTF_8), LIMITS, readBody));
            } catch (final io.helixiam.common.net.SsrfBlockedException e) {
                throw e; // a refused URL stays an SSRF refusal (a configuration failure for the drivers)
            } catch (final IllegalArgumentException e) {
                throw new RuntimeException("HTTP send failed: " + e.getMessage(), e); // as the JDK client's was
            }
        }
    }
}
