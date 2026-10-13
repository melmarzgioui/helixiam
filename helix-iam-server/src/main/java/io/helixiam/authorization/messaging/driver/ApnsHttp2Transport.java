/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.driver;

import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.SsrfBlockedException;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The APNs transport. APNs speaks HTTP/2 only, which {@link io.helixiam.common.net.PinnedHttpFetcher} (HTTP/1.1) does
 * not, so APNs goes over the JDK {@link HttpClient} with HTTP/2 and redirects off. That client resolves the host itself,
 * so this transport calls only Apple's two fixed, public APNs hosts ({@value #PRODUCTION_HOST},
 * {@value #SANDBOX_HOST}, https on 443, no user info): no realm or client setting can point it anywhere else
 * ({@link ApnsPushDriver} refuses any other {@code host}), so no attacker-chosen name is ever resolved. The outbound
 * guard still checks the URL first.
 */
public final class ApnsHttp2Transport implements HttpTransport {

    public static final String PRODUCTION_HOST = "api.push.apple.com";
    public static final String SANDBOX_HOST = "api.sandbox.push.apple.com";
    private static final Set<String> APPLE_HOSTS = Set.of(PRODUCTION_HOST, SANDBOX_HOST);

    private final OutboundUrlGuard guard;
    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public ApnsHttp2Transport(final OutboundUrlGuard guard) {
        this.guard = Objects.requireNonNull(guard, "guard");
    }

    HttpClient client() {
        return client;
    }

    /** True for {@code https://api.push.apple.com[:443]/...} or the sandbox host, without user info. */
    public static boolean isAppleHost(final String url) {
        try {
            final URI uri = new URI(url);
            return "https".equalsIgnoreCase(uri.getScheme()) && uri.getRawUserInfo() == null
                    && uri.getHost() != null && APPLE_HOSTS.contains(uri.getHost().toLowerCase(Locale.ROOT))
                    && (uri.getPort() == -1 || uri.getPort() == 443);
        } catch (final java.net.URISyntaxException | RuntimeException e) {
            return false;
        }
    }

    @Override
    public int post(final String url, final Map<String, String> headers, final String body) {
        if (!isAppleHost(url)) {
            throw new SsrfBlockedException("APNs is sent only to " + PRODUCTION_HOST + " or " + SANDBOX_HOST);
        }
        guard.checkAllowed(url);
        try {
            final HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10))
                    .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body, StandardCharsets.UTF_8));
            if (headers != null) {
                headers.forEach(b::header);
            }
            return client.send(b.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("HTTP send failed: interrupted", e);
        } catch (final Exception e) {
            throw new RuntimeException("HTTP send failed: " + e.getMessage(), e);
        }
    }
}
