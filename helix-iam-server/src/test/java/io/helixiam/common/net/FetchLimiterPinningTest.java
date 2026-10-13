/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Waiting for a fetch slot must not pin virtual-thread carriers (the review's PinProbe and LoginStall): with 1,000
 * virtual threads of one realm waiting for that realm's exhausted share, another realm's fetch, and a fetch of another
 * group, still get their slots at once. A monitor wait ({@code synchronized} / {@code Object.wait}) pins the carrier
 * on JDK 21, so the waiters took every carrier and nothing else ran.
 */
class FetchLimiterPinningTest {

    private static final int WAITERS = 1_000;

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void waitersOfOneRealmDoNotPinCarriersAndAnotherRealmStillGetsASlot() throws Exception {
        final FetchLimiter limiter = new FetchLimiter(32, 8);
        for (int i = 0; i < 8; i++) {
            assertThat(limiter.acquire(System.nanoTime() + TimeUnit.SECONDS.toNanos(1), "attacker")).isTrue();
        }
        final ExecutorService virtualThreads = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());
        try {
            for (int i = 0; i < WAITERS; i++) {
                virtualThreads.submit(() -> limiter.acquire(System.nanoTime() + TimeUnit.SECONDS.toNanos(10),
                        "attacker"));
            }
            Thread.sleep(500);
            final long start = System.nanoTime();
            final Future<Boolean> victim = virtualThreads.submit(() -> limiter.acquire(
                    System.nanoTime() + TimeUnit.SECONDS.toNanos(20), "victim"));
            assertThat(victim.get(30, TimeUnit.SECONDS)).isTrue();
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(1));
        } finally {
            virtualThreads.shutdownNow();
        }
    }

    @Test
    @Timeout(value = 60, unit = TimeUnit.SECONDS)
    void waitersOfOneGroupDoNotStallAFetchOfAnotherGroup() throws Exception {
        final HttpServer server = HttpServer.create(new InetSocketAddress(
                InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        server.createContext("/", x -> {
            final byte[] b = "{\"keys\":[]}".getBytes();
            x.sendResponseHeaders(200, b.length);
            x.getResponseBody().write(b);
            x.close();
        });
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        final FetchLimiter outbound = new FetchLimiter(32, 8);
        final ExecutorService virtualThreads = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());
        try {
            for (int i = 0; i < 8; i++) {
                outbound.acquire(System.nanoTime() + TimeUnit.SECONDS.toNanos(1), "attacker");
            }
            for (int i = 0; i < WAITERS; i++) {
                virtualThreads.submit(() -> outbound.acquire(System.nanoTime() + TimeUnit.SECONDS.toNanos(10),
                        "attacker"));
            }
            Thread.sleep(500);
            final int port = server.getAddress().getPort();
            final PinnedHttpFetcher login = new PinnedHttpFetcher(new OutboundUrlGuard(false,
                    List.of("127.0.0.1:" + port), InetAddress::getAllByName), javax.net.ssl.SSLContext.getDefault(),
                    new FetchLimiter(32, 8), () -> "victim");
            final long start = System.nanoTime();
            final PinnedHttpFetcher.Response r = login.get("http://127.0.0.1:" + port + "/jwks", Map.of(),
                    new PinnedHttpFetcher.Limits(Duration.ofMillis(500), Duration.ofSeconds(3), 50_000,
                            Duration.ofMillis(500)));
            assertThat(r.status()).isEqualTo(200);
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(1));
        } finally {
            virtualThreads.shutdownNow();
            server.stop(0);
        }
    }
}
