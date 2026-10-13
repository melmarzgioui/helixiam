/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/** The SIEM webhook is bounded in time and in backlog: a stalled SIEM costs at most the request timeout per POST. */
class HttpAuditForwarderTimeoutTest {

    private ServerSocket stalled;
    private final List<Socket> held = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startStalledSiem() throws Exception {
        stalled = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        final Thread t = new Thread(() -> {
            while (!stalled.isClosed()) {
                try {
                    held.add(stalled.accept()); // read nothing, answer nothing
                } catch (final Exception e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }

    @AfterEach
    void stop() throws Exception {
        stalled.close();
        for (final Socket s : held) {
            s.close();
        }
    }

    private HelixAuditProperties props(final int timeoutMs) {
        final HelixAuditProperties props = new HelixAuditProperties();
        props.getHttp().setUrl("http://127.0.0.1:" + stalled.getLocalPort() + "/siem");
        props.getHttp().setTimeoutMs(timeoutMs);
        return props;
    }

    @Test
    void aStalledSiemIsAbandonedAfterTheRequestTimeout() {
        final HttpAuditForwarder forwarder = new HttpAuditForwarder(props(300));
        final long start = System.nanoTime();
        assertThat(forwarder.post("{}")).isFalse();
        assertThat((System.nanoTime() - start) / 1_000_000).isLessThan(3_000);
    }

    @Test
    void aMissingOrAbsurdTimeoutFallsBackToABoundedOne() {
        assertThat(new HttpAuditForwarder(props(0)).requestTimeout().toMillis()).isEqualTo(2_000);
        assertThat(new HttpAuditForwarder(props(-5)).requestTimeout().toMillis()).isEqualTo(2_000);
        assertThat(new HttpAuditForwarder(props(Integer.MAX_VALUE)).requestTimeout().toMillis()).isEqualTo(30_000);
        final HttpAuditForwarder forwarder = new HttpAuditForwarder(props(0));
        final long start = System.nanoTime();
        assertThat(forwarder.post("{}")).isFalse();
        assertThat((System.nanoTime() - start) / 1_000_000).isBetween(1_000L, 6_000L); // bounded, not instant failure
    }

    @Test
    void theBacklogIsBoundedAndOverflowIsDropped() {
        final HttpAuditForwarder forwarder = new HttpAuditForwarder(props(30_000));
        for (int i = 0; i < 5_000; i++) {
            forwarder.forward("{\"n\":" + i + "}");
        }
        assertThat(forwarder.pending()).isLessThanOrEqualTo(HttpAuditForwarder.MAX_PENDING);
        assertThat(forwarder.dropped()).isGreaterThan(0);
    }
}
