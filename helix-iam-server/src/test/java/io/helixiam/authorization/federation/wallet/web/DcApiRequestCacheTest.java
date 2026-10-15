/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.wallet.AuthorizationRequestFactory.DcApiRequest;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link DcApiRequestCache}: one signature per transaction (a repeat call returns the same request), at most
 * {@link DcApiRequestCache#MAX_FETCHES} fetches per transaction, entries gone at the transaction's expiry, bounded size.
 */
class DcApiRequestCacheTest {

    private static final Instant NOW = Instant.parse("2026-10-15T12:00:00Z");

    private final AtomicInteger signed = new AtomicInteger();
    private final Supplier<DcApiRequest> sign = () -> new DcApiRequest("openid4vp-v1-signed",
            Map.of("request", "jws-" + signed.incrementAndGet()));

    @Test
    void aRepeatCall_returnsTheSameRequest_withoutSigningAgain() {
        final DcApiRequestCache cache = new DcApiRequestCache(Clock.fixed(NOW, ZoneOffset.UTC), 100);

        final DcApiRequest first = cache.fetch("tx-1", NOW.plusSeconds(300), sign).orElseThrow();
        final DcApiRequest again = cache.fetch("tx-1", NOW.plusSeconds(300), sign).orElseThrow();

        assertThat(again).isSameAs(first);
        assertThat(signed).hasValue(1);
        assertThat(cache.fetch("tx-2", NOW.plusSeconds(300), sign).orElseThrow().data()).containsEntry("request", "jws-2");
    }

    @Test
    void theEleventhFetchOfATransaction_isRefused() {
        final DcApiRequestCache cache = new DcApiRequestCache(Clock.fixed(NOW, ZoneOffset.UTC), 100);

        for (int i = 0; i < DcApiRequestCache.MAX_FETCHES; i++) {
            assertThat(cache.fetch("tx-1", NOW.plusSeconds(300), sign)).as("fetch " + (i + 1)).isPresent();
        }
        assertThat(cache.fetch("tx-1", NOW.plusSeconds(300), sign)).isEmpty();
        assertThat(cache.fetch("tx-2", NOW.plusSeconds(300), sign)).as("other transactions are not affected")
                .isPresent();
        assertThat(signed).hasValue(2);
    }

    @Test
    void entriesExpireWithTheirTransaction_andTheCacheStaysBounded() {
        final Instant[] now = {NOW};
        final Clock clock = new Clock() {
            @Override
            public java.time.ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(final java.time.ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now[0];
            }
        };
        final DcApiRequestCache cache = new DcApiRequestCache(clock, 3);
        cache.fetch("tx-1", NOW.plusSeconds(10), sign);
        now[0] = NOW.plusSeconds(10);
        assertThat(cache.fetch("tx-1", NOW.plusSeconds(10), sign).orElseThrow().data())
                .as("expired: signed afresh (the caller refuses an expired transaction anyway)")
                .containsEntry("request", "jws-2");

        for (int i = 0; i < 10; i++) {
            cache.fetch("many-" + i, NOW.plusSeconds(300), sign);
        }
        assertThat(cache.size()).isLessThanOrEqualTo(3);
    }
}
