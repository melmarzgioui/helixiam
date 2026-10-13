/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import com.sun.net.httpserver.HttpServer;
import io.helixiam.common.net.PinnedHttpFetcher.FetchException;
import io.helixiam.common.net.PinnedHttpFetcher.Limits;
import io.helixiam.common.net.PinnedHttpFetcher.Request;
import io.helixiam.common.net.PinnedHttpFetcher.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The general request API of {@link PinnedHttpFetcher} that the guard's other callers (webhooks, SCIM, notification
 * drivers, logout, OIDC, JWKS, eID) use: every method with a body, response headers, error bodies, charsets, the
 * client-owned headers, and the Nimbus {@link PinnedResourceRetriever}.
 */
class PinnedHttpExchangeTest {

    private static final Limits LIMITS = new Limits(Duration.ofSeconds(3), Duration.ofSeconds(5), 1024);

    /** method, path, Content-Length, User-Agent, body, as the server saw them. */
    record Seen(String method, String path, String contentLength, String userAgent, String body) {
    }

    private HttpServer server;
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private volatile int status = 200;
    private volatile byte[] answer = "ok".getBytes(StandardCharsets.US_ASCII);
    private volatile String contentType = "text/plain";

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        server.createContext("/", exchange -> {
            try (exchange) {
                final byte[] body = exchange.getRequestBody().readAllBytes();
                seen.add(new Seen(exchange.getRequestMethod(), exchange.getRequestURI().getRawPath(),
                        exchange.getRequestHeaders().getFirst("Content-Length"),
                        exchange.getRequestHeaders().getFirst("User-Agent"),
                        new String(body, StandardCharsets.UTF_8)));
                exchange.getResponseHeaders().add("Content-Type", contentType);
                exchange.getResponseHeaders().add("X-Request-Id", "abc");
                exchange.getResponseHeaders().add("X-Multi", "1");
                exchange.getResponseHeaders().add("X-Multi", "2");
                final byte[] b = answer;
                final boolean head = "HEAD".equals(exchange.getRequestMethod());
                exchange.sendResponseHeaders(status, head || status == 204 ? -1 : b.length == 0 ? -1 : b.length);
                if (!head && status != 204 && b.length > 0) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(b);
                    }
                }
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String url(final String path) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    private static PinnedHttpFetcher fetcher() {
        return PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());
    }

    @Test
    void everyMethodCarriesItsBody() throws Exception {
        for (final String method : List.of("POST", "PUT", "PATCH", "DELETE")) {
            fetcher().exchange(new Request(method, url("/u"), Map.of("Content-Type", "application/scim+json"),
                    ("{\"m\":\"" + method + "\"}").getBytes(StandardCharsets.UTF_8), LIMITS, false));
        }
        assertThat(seen).extracting(Seen::method).containsExactly("POST", "PUT", "PATCH", "DELETE");
        assertThat(seen).extracting(Seen::body).containsExactly("{\"m\":\"POST\"}", "{\"m\":\"PUT\"}",
                "{\"m\":\"PATCH\"}", "{\"m\":\"DELETE\"}");
    }

    @Test
    void aBodylessPostStatesAnEmptyBodyAndABodylessDeleteDoesNot() throws Exception {
        fetcher().exchange(new Request("POST", url("/p"), Map.of(), null, LIMITS, false));
        fetcher().exchange(new Request("DELETE", url("/d"), Map.of(), null, LIMITS, false));
        assertThat(seen.get(0).contentLength()).isEqualTo("0");
        assertThat(seen.get(1).contentLength()).isNull();
    }

    @Test
    void errorBodiesAreReadOnlyWhenAsked() throws Exception {
        status = 400;
        answer = "{\"error\":\"invalid_grant\"}".getBytes(StandardCharsets.UTF_8);
        assertThat(fetcher().exchange(new Request("POST", url("/t"), Map.of(), new byte[0], LIMITS, true))
                .bodyAsString()).isEqualTo("{\"error\":\"invalid_grant\"}");
        assertThat(fetcher().exchange(new Request("POST", url("/t"), Map.of(), new byte[0], LIMITS, false))
                .body()).isEmpty();
    }

    @Test
    void responseHeadersAndCharsetAreExposed() throws Exception {
        contentType = "text/plain; charset=ISO-8859-1";
        answer = "café".getBytes(StandardCharsets.ISO_8859_1);
        final Response r = fetcher().get(url("/h"), Map.of(), LIMITS);
        assertThat(r.header("x-request-id")).isEqualTo("abc");
        assertThat(r.headers().get("X-Multi")).containsExactly("1", "2");
        assertThat(r.bodyAsString()).isEqualTo("café");
        contentType = "application/json";
        answer = "é".getBytes(StandardCharsets.UTF_8);
        assertThat(fetcher().get(url("/h"), Map.of(), LIMITS).bodyAsString()).isEqualTo("é");
    }

    @Test
    void headAnd204HaveNoBody() throws Exception {
        assertThat(fetcher().exchange(new Request("HEAD", url("/x"), Map.of(), null, LIMITS, true)).body()).isEmpty();
        status = 204;
        assertThat(fetcher().exchange(new Request("DELETE", url("/x"), Map.of(), null, LIMITS, true)).status())
                .isEqualTo(204);
    }

    @Test
    void theCallersUserAgentReplacesTheDefault() throws Exception {
        fetcher().get(url("/a"), Map.of("User-Agent", "Caller/1"), LIMITS);
        fetcher().get(url("/b"), Map.of(), LIMITS);
        assertThat(seen).extracting(Seen::userAgent).containsExactly("Caller/1", "HelixIAM");
    }

    @Test
    void clientOwnedHeadersAndUnknownMethodsAreRefusedBeforeConnecting() {
        for (final String header : List.of("Host", "content-length", "Connection", "Transfer-Encoding", "Expect",
                "Upgrade")) {
            assertThatThrownBy(() -> fetcher().get(url("/x"), Map.of(header, "1"), LIMITS)).as(header)
                    .isInstanceOf(IllegalArgumentException.class);
        }
        for (final String method : List.of("CONNECT", "TRACE", "get", "G ET")) {
            assertThatThrownBy(() -> fetcher().exchange(new Request(method, url("/x"), Map.of(), null, LIMITS, false)))
                    .as(method).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(seen).isEmpty();
    }

    @Test
    void anOversizedBodyReportsItsStatus() {
        status = 502;
        answer = new byte[4096];
        assertThatThrownBy(() -> fetcher().exchange(new Request("POST", url("/x"), Map.of(), new byte[0], LIMITS,
                true))).isInstanceOfSatisfying(FetchException.class, e -> {
                    assertThat(e.kind()).isEqualTo(FetchException.Kind.TOO_LARGE);
                    assertThat(e.status()).isEqualTo(502);
                });
    }

    @Test
    void theResourceRetrieverFetchesThroughThePinnedConnection() throws Exception {
        contentType = "application/jwk-set+json";
        answer = "{\"keys\":[]}".getBytes(StandardCharsets.UTF_8);
        final AtomicInteger lookups = new AtomicInteger();
        final int port = server.getAddress().getPort();
        final OutboundUrlGuard rebinding = new OutboundUrlGuard(false, List.of("jwks.test:" + port), host -> {
            final byte[] ip = lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                    : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
            return new InetAddress[] {InetAddress.getByAddress(host, ip)};
        });
        final PinnedResourceRetriever retriever = new PinnedResourceRetriever(rebinding);

        final com.nimbusds.jose.util.Resource r = retriever.retrieveResource(
                new URL("http://jwks.test:" + port + "/jwks"));

        assertThat(r.getContent()).isEqualTo("{\"keys\":[]}");
        assertThat(r.getContentType()).isEqualTo("application/jwk-set+json");
        assertThat(lookups).hasValue(1);
        status = 404;
        assertThatThrownBy(() -> new PinnedResourceRetriever(OutboundUrlGuard.permissive())
                .retrieveResource(new URL(url("/jwks")))).isInstanceOf(java.io.IOException.class);
        assertThatThrownBy(() -> new PinnedResourceRetriever(OutboundUrlGuard.blocking())
                .retrieveResource(new URL(url("/jwks")))).isInstanceOf(java.io.IOException.class);
    }
}
