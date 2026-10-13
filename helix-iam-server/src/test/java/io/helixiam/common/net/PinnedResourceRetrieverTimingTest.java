/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * JWKS fetch timing: Nimbus-like per-phase limits (500 ms connect, 500 ms between reads) and a 3 s total, DNS and TLS
 * included.
 */
class PinnedResourceRetrieverTimingTest {

    /** Answers with the headers and then {@code bytes} body bytes, one every {@code gapMillis}. */
    private static ServerSocket drip(final int bytes, final long gapMillis) throws Exception {
        final ServerSocket ss = new ServerSocket(0, 10, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}));
        final Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (Socket s = ss.accept()) {
                    final OutputStream out = s.getOutputStream();
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + bytes
                            + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                    for (int i = 0; i < bytes; i++) {
                        Thread.sleep(gapMillis);
                        out.write(' ');
                        out.flush();
                    }
                } catch (final Exception e) {
                    // next
                }
            }
        }, "drip");
        t.setDaemon(true);
        t.start();
        return ss;
    }

    @Test
    void theDefaultsAreNimbusLikePerPhaseWithAThreeSecondTotal() {
        assertThat(PinnedResourceRetriever.DEFAULT_CONNECT_TIMEOUT).isEqualTo(Duration.ofMillis(500));
        assertThat(PinnedResourceRetriever.DEFAULT_READ_TIMEOUT).isEqualTo(Duration.ofMillis(500));
        assertThat(PinnedResourceRetriever.DEFAULT_TOTAL_TIMEOUT).isEqualTo(Duration.ofSeconds(3));
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void aStallBetweenReadsLongerThanTheReadTimeoutFails() throws Exception {
        try (ServerSocket ss = drip(2, 900)) {
            final long start = System.nanoTime();
            assertThatThrownBy(() -> new PinnedResourceRetriever(OutboundUrlGuard.permissive())
                    .retrieveResource(new URL("http://127.0.0.1:" + ss.getLocalPort() + "/jwks")))
                    .isInstanceOf(java.io.IOException.class);
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1_500));
        }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void aSlowDripWithinTheReadTimeoutIsStillCutAtTheTotal() throws Exception {
        try (ServerSocket ss = drip(40, 300)) { // 12 s of body, each gap under the read timeout
            final long start = System.nanoTime();
            assertThatThrownBy(() -> new PinnedResourceRetriever(OutboundUrlGuard.permissive())
                    .retrieveResource(new URL("http://127.0.0.1:" + ss.getLocalPort() + "/jwks")))
                    .isInstanceOf(java.io.IOException.class);
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isBetween(Duration.ofMillis(2_800),
                    Duration.ofMillis(3_800));
        }
    }
}
