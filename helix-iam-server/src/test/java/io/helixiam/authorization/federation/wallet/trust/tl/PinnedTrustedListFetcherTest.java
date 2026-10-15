/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.helixiam.authorization.messaging.email.TlsTrust;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListLoaderTest.assertKind;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link PinnedTrustedListFetcher}: the pinned, guarded transport for trusted lists. A 200 body comes back; a
 * redirect, an oversized body, plain http and a host the egress guard refuses do not.
 */
class PinnedTrustedListFetcherTest {

    static TestTls tls;
    HttpsServer server;
    final AtomicInteger hits = new AtomicInteger();

    @BeforeAll
    static void tls() {
        tls = TestTls.create("trusted-list");
    }

    @BeforeEach
    void start() throws Exception {
        server = HttpsServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(tls.serverContext()));
        server.createContext("/list.xml", ex -> {
            hits.incrementAndGet();
            final byte[] body = "<list/>".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.createContext("/moved.xml", ex -> {
            hits.incrementAndGet();
            ex.getResponseHeaders().add("Location", url("/list.xml"));
            ex.sendResponseHeaders(302, -1);
            ex.close();
        });
        server.createContext("/big.xml", ex -> {
            hits.incrementAndGet();
            final byte[] body = new byte[4096];
            ex.sendResponseHeaders(200, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.createContext("/gone.xml", ex -> {
            hits.incrementAndGet();
            ex.sendResponseHeaders(404, -1);
            ex.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    String url(final String path) {
        return "https://localhost:" + server.getAddress().getPort() + path;
    }

    PinnedTrustedListFetcher fetcher(final long maxBytes) {
        return new PinnedTrustedListFetcher(new OutboundUrlGuard(false,
                "localhost:" + server.getAddress().getPort()), TlsTrust.context(tls.caPem()), maxBytes);
    }

    @Test
    void okBody_isReturned() throws Exception {
        assertThat(new String(fetcher(1024).fetch(url("/list.xml"), "r"), StandardCharsets.UTF_8)).isEqualTo("<list/>");
    }

    @Test
    void redirect_isRefused_andNotFollowed() {
        assertKind(() -> fetcher(1024).fetch(url("/moved.xml"), "r"), TrustedListException.Kind.REDIRECT);
        assertThat(hits.get()).isEqualTo(1);
    }

    @Test
    void oversizedBody_isRefused() {
        assertKind(() -> fetcher(1024).fetch(url("/big.xml"), "r"), TrustedListException.Kind.TOO_LARGE);
    }

    @Test
    void errorStatus_isAFetchFailure() {
        assertThat(assertKind(() -> fetcher(1024).fetch(url("/gone.xml"), "r"), TrustedListException.Kind.FETCH))
                .hasMessageContaining("404");
    }

    @Test
    void plainHttp_isRefusedBeforeConnecting() {
        assertKind(() -> fetcher(1024).fetch("http://localhost:" + server.getAddress().getPort() + "/list.xml", "r"),
                TrustedListException.Kind.POLICY);
        assertThat(hits.get()).isZero();
    }

    @Test
    void loopback_isRefusedByTheProductionGuard() {
        final PinnedTrustedListFetcher guarded = new PinnedTrustedListFetcher(new OutboundUrlGuard(false),
                TlsTrust.context(tls.caPem()), 1024);
        assertKind(() -> guarded.fetch(url("/list.xml"), "r"), TrustedListException.Kind.POLICY);
        assertThat(hits.get()).isZero();
    }

    @Test
    void untrustedServerCertificate_isAFetchFailure() {
        final PinnedTrustedListFetcher strict = new PinnedTrustedListFetcher(new OutboundUrlGuard(false,
                "localhost:" + server.getAddress().getPort()), TlsTrust.context(null), 1024);
        assertKind(() -> strict.fetch(url("/list.xml"), "r"), TrustedListException.Kind.FETCH);
    }
}
