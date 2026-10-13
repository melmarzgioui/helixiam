/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A fetch that names no realm counts against a bounded "(no realm)" partition of its group, like a realm: it can
 * neither take every slot of the group nor be shut out by one realm.
 */
class NoRealmPartitionTest {

    @Test
    void fetchesWithoutARealmShareOneBoundedPartition() throws Exception {
        final FetchLimiter limiter = new FetchLimiter(4, 2);
        for (int i = 0; i < 2; i++) {
            assertThat(limiter.acquire(System.nanoTime() + 50_000_000L, PinnedHttpFetcher.NO_REALM)).isTrue();
        }
        try (ServerSocket closed = new ServerSocket(0)) {
            final PinnedHttpFetcher noRealm = new PinnedHttpFetcher(OutboundUrlGuard.permissive(),
                    javax.net.ssl.SSLContext.getDefault(), limiter, () -> null);
            // the no-realm share is full: a no-realm fetch waits for it and times out
            assertThatThrownBy(() -> noRealm.get("http://127.0.0.1:" + closed.getLocalPort() + "/x", Map.of(),
                    new PinnedHttpFetcher.Limits(Duration.ofMillis(200), Duration.ofMillis(300), 100)))
                    .isInstanceOfSatisfying(PinnedHttpFetcher.FetchException.class,
                            e -> assertThat(e.getMessage()).contains("free slot"));
            // a realm still gets its own share
            assertThat(limiter.acquire(System.nanoTime() + 50_000_000L, "acme")).isTrue();
        }
    }

    @Test
    void theAdminMetadataFetchCountsAgainstTheRealmItIsFor() {
        final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of(), host -> new InetAddress[] {
                InetAddress.getByAddress(host, new byte[] {10, 0, 0, 1})});
        assertThatThrownBy(() -> guard.fetch("https://md.example/x", "text/xml", true, "acme"))
                .isInstanceOf(SsrfBlockedException.class);
    }
}
