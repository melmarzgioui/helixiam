/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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

    @Component
    class Default implements HttpTransport {
        private final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

        @Override
        public int post(final String url, final Map<String, String> headers, final String body) {
            return send(url, headers, body, HttpResponse.BodyHandlers.discarding()).statusCode();
        }

        @Override
        public Response postForResponse(final String url, final Map<String, String> headers, final String body) {
            final HttpResponse<String> r = send(url, headers, body, HttpResponse.BodyHandlers.ofString());
            return new Response(r.statusCode(), r.body());
        }

        private <T> HttpResponse<T> send(final String url, final Map<String, String> headers, final String body,
                                         final HttpResponse.BodyHandler<T> handler) {
            try {
                final HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                        .timeout(Duration.ofSeconds(10))
                        .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
                if (headers != null) {
                    headers.forEach(b::header);
                }
                return httpClient.send(b.build(), handler);
            } catch (final Exception e) {
                throw new RuntimeException("HTTP send failed: " + e.getMessage(), e);
            }
        }
    }
}
