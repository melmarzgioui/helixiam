/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;

import java.io.IOException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * A Nimbus {@link ResourceRetriever} (JWKS fetches by {@code JWKSourceBuilder} / {@code RemoteJWKSet}) over
 * {@link PinnedHttpFetcher}: the URL passes the outbound guard on every fetch, the connection goes to the validated
 * address, redirects are not followed. Nimbus's own default retriever ({@code HttpURLConnection}) re-resolves the host
 * after the guard's check and follows redirects. The limits follow Nimbus's per phase, 500 ms to connect and 500 ms for
 * each read (TLS handshake included), plus 3 s for the whole fetch (DNS, connect, TLS and body), and a 50 KB size
 * limit.
 */
public final class PinnedResourceRetriever implements ResourceRetriever {

    /** Nimbus's JWKS defaults per phase (500 ms connect, 500 ms read, 50 KB), plus a 3 s total. */
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofMillis(500);
    public static final Duration DEFAULT_READ_TIMEOUT = Duration.ofMillis(500);
    public static final Duration DEFAULT_TOTAL_TIMEOUT = Duration.ofSeconds(3);
    public static final int DEFAULT_SIZE_LIMIT = 50 * 1024;
    private static final PinnedHttpFetcher.Limits DEFAULT_LIMITS = new PinnedHttpFetcher.Limits(
            DEFAULT_CONNECT_TIMEOUT, DEFAULT_TOTAL_TIMEOUT, DEFAULT_SIZE_LIMIT, DEFAULT_READ_TIMEOUT);

    private final PinnedHttpFetcher fetcher;
    private final PinnedHttpFetcher.Limits limits;

    /** Nimbus-default limits. */
    public PinnedResourceRetriever(final OutboundUrlGuard guard) {
        this(PinnedHttpFetcher.plain(guard), DEFAULT_LIMITS);
    }

    /** Nimbus-default limits, slots from {@code group}, per-realm sub-cap by {@code partition}. */
    public PinnedResourceRetriever(final OutboundUrlGuard guard, final FetchLimiter.Group group,
            final java.util.function.Supplier<String> partition) {
        this(PinnedHttpFetcher.plain(guard, group, partition), DEFAULT_LIMITS);
    }

    public PinnedResourceRetriever(final PinnedHttpFetcher fetcher, final PinnedHttpFetcher.Limits limits) {
        this.fetcher = Objects.requireNonNull(fetcher, "fetcher");
        this.limits = Objects.requireNonNull(limits, "limits");
    }

    /**
     * GETs {@code url}. Any failure, including a refusal by the guard, is an {@link IOException} (what Nimbus expects
     * from a retriever); a status outside 2xx is one too.
     */
    @Override
    public Resource retrieveResource(final URL url) throws IOException {
        final PinnedHttpFetcher.Response r;
        try {
            r = fetcher.exchange(new PinnedHttpFetcher.Request("GET", url.toString(),
                    Map.of("Accept", "application/jwk-set+json, application/json"), null, limits, true));
        } catch (final SsrfBlockedException e) {
            throw new IOException("Blocked outbound URL (SSRF guard)", e);
        }
        if (r.status() / 100 != 2) {
            throw new IOException("HTTP " + r.status() + " fetching the resource");
        }
        return new Resource(r.bodyAsString(), r.contentType());
    }
}
