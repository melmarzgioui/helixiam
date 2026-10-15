/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.common.net.FetchLimiter;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.net.PinnedHttpFetcher;
import io.helixiam.common.net.SsrfBlockedException;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Fetches trusted lists over {@link PinnedHttpFetcher}: https only, the host checked by {@link OutboundUrlGuard} and
 * resolved once (the connection goes to the checked address, so DNS rebinding cannot redirect it), the certificate
 * verified against the host name, no redirects (a 3xx is a {@link TrustedListException.Kind#REDIRECT} refusal), a size
 * cap, a 5 s connect and 30 s total deadline (DNS included), and a slot of the {@code WALLET} fetch-limiter group in
 * the realm's partition, so list refreshes cannot take more than their share of outbound slots.
 */
public final class PinnedTrustedListFetcher implements TrustedListFetcher {

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    static final Duration TOTAL_TIMEOUT = Duration.ofSeconds(30);
    static final Duration READ_TIMEOUT = Duration.ofSeconds(10);
    private static final String ACCEPT = "application/vnd.etsi.tsl+xml, application/xml, text/xml, application/json, "
            + "application/jose, */*;q=0.1";

    private final PinnedHttpFetcher fetcher;
    private final long maxBytes;

    public PinnedTrustedListFetcher(final OutboundUrlGuard guard, final SSLContext sslContext, final long maxBytes) {
        this.fetcher = new PinnedHttpFetcher(Objects.requireNonNull(guard, "guard"),
                Objects.requireNonNull(sslContext, "sslContext"), FetchLimiter.forGroup(FetchLimiter.Group.WALLET));
        this.maxBytes = maxBytes;
    }

    @Override
    public byte[] fetch(final String url, final String realm) throws TrustedListException {
        final URI uri;
        try {
            uri = new URI(url == null ? "" : url.trim());
        } catch (final Exception e) {
            throw new TrustedListException(TrustedListException.Kind.POLICY, "the list URL is not a valid URL");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            throw new TrustedListException(TrustedListException.Kind.POLICY, "the list URL must be https");
        }
        final PinnedHttpFetcher.Response response;
        try {
            response = fetcher.exchange(new PinnedHttpFetcher.Request("GET", uri.toString(), Map.of("Accept", ACCEPT),
                    null, new PinnedHttpFetcher.Limits(CONNECT_TIMEOUT, TOTAL_TIMEOUT, maxBytes, READ_TIMEOUT), false,
                    realm));
        } catch (final SsrfBlockedException e) {
            throw new TrustedListException(TrustedListException.Kind.POLICY,
                    "the list host is not allowed (private, loopback or unresolvable address)");
        } catch (final PinnedHttpFetcher.FetchException e) {
            if (e.kind() == PinnedHttpFetcher.FetchException.Kind.TOO_LARGE) {
                throw new TrustedListException(TrustedListException.Kind.TOO_LARGE,
                        "the list is larger than the size cap");
            }
            throw new TrustedListException(TrustedListException.Kind.FETCH, "the list could not be fetched: "
                    + e.getMessage());
        }
        final int status = response.status();
        if (status / 100 == 3) {
            throw new TrustedListException(TrustedListException.Kind.REDIRECT,
                    "the list URL answered with a redirect (HTTP " + status + "); redirects are not followed, "
                            + "configure the final URL");
        }
        if (status != 200) {
            throw new TrustedListException(TrustedListException.Kind.FETCH, "the list URL answered HTTP " + status);
        }
        return response.body();
    }
}
