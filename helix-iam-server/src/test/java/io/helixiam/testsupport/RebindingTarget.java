/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.helixiam.common.net.OutboundUrlGuard;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * A DNS-rebinding scenario for an outbound caller: a local HTTP(S) server and a guard whose resolver answers the host
 * name with the server's address the first time and with the cloud-metadata address {@code 169.254.169.254} every
 * time after. A caller that connects to the address the guard validated reaches the server with exactly one lookup; a
 * caller that resolved the name again (the JDK clients do) would be sent to the metadata address instead. The first
 * answer is the loopback address the server listens on, allowed for this one name through the guard's private-host
 * allowlist; a test cannot listen on a public address.
 */
public final class RebindingTarget implements AutoCloseable {

    /** One request the server received. */
    public record Seen(String method, String path, Map<String, List<String>> headers, String body) {
        public String header(final String name) {
            for (final Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey().equalsIgnoreCase(name) && !e.getValue().isEmpty()) {
                    return e.getValue().get(0);
                }
            }
            return null;
        }
    }

    /** A canned answer. */
    public record Answer(int status, String contentType, String body) {
    }

    private final String host;
    private final HttpServer server;
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private final AtomicInteger lookups = new AtomicInteger();
    private volatile Function<Seen, Answer> responder = s -> new Answer(200, "application/json", "{}");

    private RebindingTarget(final String host, final TestTls tls) throws IOException {
        this.host = host;
        final InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0);
        if (tls != null) {
            final HttpsServer s = HttpsServer.create(address, 0);
            s.setHttpsConfigurator(new HttpsConfigurator(tls.serverContext()));
            server = s;
        } else {
            server = HttpServer.create(address, 0);
        }
        server.createContext("/", exchange -> {
            try (exchange) {
                final String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                final Seen s = new Seen(exchange.getRequestMethod(), exchange.getRequestURI().getRawPath()
                        + (exchange.getRequestURI().getRawQuery() == null ? ""
                        : "?" + exchange.getRequestURI().getRawQuery()),
                        Map.copyOf(exchange.getRequestHeaders()), body);
                seen.add(s);
                final Answer a = responder.apply(s);
                if (a.contentType() != null) {
                    exchange.getResponseHeaders().add("Content-Type", a.contentType());
                }
                final byte[] b = a.body() == null ? new byte[0] : a.body().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(a.status(), b.length == 0 ? -1 : b.length);
                if (b.length > 0) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(b);
                    }
                }
            }
        });
        server.start();
    }

    /** Plain HTTP for {@code host}. */
    public static RebindingTarget http(final String host) {
        try {
            return new RebindingTarget(host, null);
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** HTTPS with a certificate for {@code host} (trust it with {@link TestTls#caPem()} of {@code tls}). */
    public static RebindingTarget https(final String host, final TestTls tls) {
        try {
            return new RebindingTarget(host, tls);
        } catch (final IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The guard of the scenario: {@code host} allowlisted on this port, answered as described above. */
    public OutboundUrlGuard guard() {
        return new OutboundUrlGuard(false, List.of(host + ":" + port()), name -> {
            final byte[] ip = lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                    : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
            return new InetAddress[] {InetAddress.getByAddress(name, ip)};
        });
    }

    /** One guard for several targets (a caller that talks to more than one host), each host answered as above. */
    public static OutboundUrlGuard guard(final RebindingTarget... targets) {
        final java.util.List<String> allow = new java.util.ArrayList<>();
        for (final RebindingTarget t : targets) {
            allow.add(t.host + ":" + t.port());
        }
        return new OutboundUrlGuard(false, allow, name -> {
            for (final RebindingTarget t : targets) {
                if (t.host.equalsIgnoreCase(name)) {
                    final byte[] ip = t.lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                            : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
                    return new InetAddress[] {InetAddress.getByAddress(name, ip)};
                }
            }
            throw new java.net.UnknownHostException(name);
        });
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /** {@code scheme://host:port} + path. */
    public String url(final String scheme, final String path) {
        return scheme + "://" + host + ":" + port() + path;
    }

    public void respond(final Function<Seen, Answer> value) {
        responder = value;
    }

    public List<Seen> requests() {
        return List.copyOf(seen);
    }

    /** How often the guard's resolver was asked; 1 per fetch when every connection is pinned. */
    public int lookups() {
        return lookups.get();
    }

    /** Resets the lookup count so the next fetch starts from the first (validated) answer again. */
    public void resetLookups() {
        lookups.set(0);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
