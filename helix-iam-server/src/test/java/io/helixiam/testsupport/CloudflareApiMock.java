/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * A local stand-in for the Cloudflare Email Service send API ({@code POST /accounts/{id}/email/sending/send}), over
 * HTTPS with a {@link TestTls} certificate (or plain HTTP, for the dev-profile case). It records every request and
 * answers what {@link #respond} says; by default {@code 200} with the recipient in {@code delivered}.
 */
public final class CloudflareApiMock implements AutoCloseable {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** One request the mock received. */
    public record Request(String method, String path, String authorization, String contentType, String body,
                          Instant at) {

        public JsonNode json() {
            try {
                return JSON.readTree(body);
            } catch (final IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        /** The first {@code to} address. */
        public String to() {
            return json().path("to").path(0).path("address").asText(null);
        }
    }

    /** A canned answer. */
    public record Response(int status, String body, long delayMillis) {

        public static Response of(final int status, final String body) {
            return new Response(status, body, 0);
        }
    }

    private final HttpServer server;
    private final boolean https;
    private final List<Request> requests = new CopyOnWriteArrayList<>();
    private volatile Function<Request, Response> responder = r -> delivered(r.to());

    private CloudflareApiMock(final TestTls tls) throws IOException {
        final InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0);
        if (tls != null) {
            final HttpsServer s = HttpsServer.create(address, 0);
            s.setHttpsConfigurator(new HttpsConfigurator(tls.serverContext()));
            server = s;
        } else {
            server = HttpServer.create(address, 0);
        }
        this.https = tls != null;
        server.createContext("/", this::handle);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
            final Thread t = new Thread(r, "cloudflare-mock");
            t.setDaemon(true);
            return t;
        }));
        server.start();
    }

    /** An HTTPS mock with {@code tls}'s certificate. */
    public static CloudflareApiMock https(final TestTls tls) {
        try {
            return new CloudflareApiMock(tls);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** A plain-HTTP mock (only a dev-profile driver may use it). */
    public static CloudflareApiMock http() {
        try {
            return new CloudflareApiMock(null);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public int port() {
        return server.getAddress().getPort();
    }

    /** The base URL to configure ({@code https://127.0.0.1:<port>/client/v4}). */
    public String baseUrl() {
        return (https ? "https" : "http") + "://127.0.0.1:" + port() + "/client/v4";
    }

    /** The base URL on the {@code localhost} name. */
    public String baseUrlOnLocalhost() {
        return (https ? "https" : "http") + "://localhost:" + port() + "/client/v4";
    }

    public CloudflareApiMock respond(final Function<Request, Response> responder) {
        this.responder = responder;
        return this;
    }

    public CloudflareApiMock respond(final int status, final String body) {
        return respond(r -> Response.of(status, body));
    }

    public List<Request> requests() {
        return List.copyOf(requests);
    }

    public Request await(final Predicate<Request> filter, final Duration timeout) {
        final Instant deadline = Instant.now().plus(timeout);
        do {
            final List<Request> matching = requests.stream().filter(filter).toList();
            if (!matching.isEmpty()) {
                return matching.get(matching.size() - 1);
            }
            try {
                Thread.sleep(50);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        } while (Instant.now().isBefore(deadline));
        throw new AssertionError("No matching request within " + timeout + "; received " + requests.size());
    }

    /** {@code 200}, {@code success: true}, the recipient delivered. */
    public static Response delivered(final String to) {
        return Response.of(200, "{\"success\":true,\"errors\":[],\"result\":{\"delivered\":[\"" + to
                + "\"],\"permanent_bounces\":[],\"queued\":[]}}");
    }

    private void handle(final HttpExchange exchange) throws IOException {
        try (exchange; InputStream in = exchange.getRequestBody()) {
            final Request request = new Request(exchange.getRequestMethod(), exchange.getRequestURI().getPath(),
                    exchange.getRequestHeaders().getFirst("Authorization"),
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    new String(in.readAllBytes(), StandardCharsets.UTF_8), Instant.now());
            requests.add(request);
            final Response response = responder.apply(request);
            if (response.delayMillis() > 0) {
                try {
                    Thread.sleep(response.delayMillis());
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            final byte[] body = response.body() == null ? new byte[0] : response.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(response.status(), body.length == 0 ? -1 : body.length);
            if (body.length > 0) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
        } catch (final IOException e) {
            // the client gave up (timeout test): fine
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
