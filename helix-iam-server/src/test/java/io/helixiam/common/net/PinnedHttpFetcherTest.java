/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import com.sun.net.httpserver.HttpServer;
import io.helixiam.common.net.PinnedHttpFetcher.FetchException;
import io.helixiam.common.net.PinnedHttpFetcher.Limits;
import io.helixiam.common.net.PinnedHttpFetcher.Response;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The pinned outbound transport: one guarded DNS resolution inside the deadline, a connection only to an address the
 * guard validated (never a fresh resolution), no redirect following, a body cap and a total deadline.
 */
class PinnedHttpFetcherTest {

    private static final Limits LIMITS = new Limits(Duration.ofSeconds(3), Duration.ofSeconds(5), 1024);

    private HttpServer server;
    private final List<String> hostHeaders = new CopyOnWriteArrayList<>();
    private final AtomicInteger hits = new AtomicInteger();
    private volatile byte[] body = "hello".getBytes(StandardCharsets.US_ASCII);
    private volatile int status = 200;
    private volatile String location;
    private volatile long delayMillis;
    private volatile boolean chunked;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
        server.createContext("/", exchange -> {
            try (exchange) {
                exchange.getRequestBody().readAllBytes();
                hits.incrementAndGet();
                hostHeaders.add(exchange.getRequestHeaders().getFirst("Host"));
                if (delayMillis > 0) {
                    Thread.sleep(delayMillis);
                }
                if (location != null) {
                    exchange.getResponseHeaders().add("Location", location);
                }
                final byte[] b = body;
                exchange.sendResponseHeaders(status, chunked ? 0 : b.length == 0 ? -1 : b.length);
                if (b.length > 0) {
                    try (OutputStream out = exchange.getResponseBody()) {
                        out.write(b);
                    }
                }
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (final java.io.IOException e) {
                // the client gave up: fine
            }
        });
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
            final Thread t = new Thread(r, "pinned-fetch-stub");
            t.setDaemon(true);
            return t;
        }));
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private int port() {
        return server.getAddress().getPort();
    }

    /** A guard that lets {@code name:port} reach loopback, resolving it with {@code resolver}. */
    private OutboundUrlGuard guard(final String name, final OutboundUrlGuard.HostResolver resolver) {
        return new OutboundUrlGuard(false, List.of(name + ":" + port()), resolver);
    }

    @Test
    void fetchesFromTheValidatedAddressWithTheOriginalHostHeader() throws Exception {
        final AtomicInteger lookups = new AtomicInteger();
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(guard("crl.test", host -> {
            lookups.incrementAndGet();
            return new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})};
        }));

        final Response response = fetcher.get("http://crl.test:" + port() + "/a.crl", Map.of(), LIMITS);

        assertThat(response.status()).isEqualTo(200);
        assertThat(new String(response.body(), StandardCharsets.US_ASCII)).isEqualTo("hello");
        assertThat(hostHeaders).containsExactly("crl.test:" + port());
        assertThat(lookups).hasValue(1);
    }

    @Test
    void dnsRebindingCannotRedirectTheConnection() throws Exception {
        // First answer: the (allowlisted) stub address. Every later answer: cloud metadata. A client that resolves
        // again after the guard's check would connect there (or fail); the pinned fetch never asks twice.
        final AtomicInteger lookups = new AtomicInteger();
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(guard("rebind.test", host -> {
            final byte[] ip = lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                    : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
            return new InetAddress[] {InetAddress.getByAddress(host, ip)};
        }));

        for (int i = 0; i < 3; i++) {
            lookups.set(0);
            assertThat(fetcher.get("http://rebind.test:" + port() + "/x", Map.of(), LIMITS).status()).isEqualTo(200);
            assertThat(lookups).hasValue(1);
        }
        assertThat(hits).hasValue(3);
    }

    @Test
    void anAddressTheGuardRefusesIsNeverConnected() {
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(new OutboundUrlGuard(false, List.of(), host ->
                new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})}));

        assertThatThrownBy(() -> fetcher.get("http://evil.test:" + port() + "/x", Map.of(), LIMITS))
                .isInstanceOf(SsrfBlockedException.class);
        assertThat(hits).hasValue(0);
    }

    @Test
    void onlyHttpAndHttpsAreFetched() {
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());
        for (final String url : List.of("ldap://ldap.example.com/cn=crl", "ftp://127.0.0.1/x", "file:///etc/passwd")) {
            assertThatThrownBy(() -> fetcher.get(url, Map.of(), LIMITS)).as(url)
                    .isInstanceOf(SsrfBlockedException.class);
        }
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void slowDnsCountsAgainstTheDeadline() {
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(guard("slow-dns.test", host -> {
            try {
                Thread.sleep(10_000);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw new UnknownHostException(host);
        }));
        final long start = System.nanoTime();

        assertThatThrownBy(() -> fetcher.get("http://slow-dns.test:" + port() + "/x", Map.of(),
                new Limits(Duration.ofSeconds(3), Duration.ofSeconds(1), 1024)))
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.TIMEOUT));
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(2_500));
        assertThat(hits).hasValue(0);
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void aSlowServerIsAbandonedAtTheTotalDeadline() {
        delayMillis = 8_000;
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());
        final long start = System.nanoTime();

        assertThatThrownBy(() -> fetcher.get("http://127.0.0.1:" + port() + "/x", Map.of(),
                new Limits(Duration.ofSeconds(3), Duration.ofSeconds(1), 1024)))
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.TIMEOUT));
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(2_500));
    }

    @Test
    void redirectsAreReturnedNotFollowed() throws Exception {
        status = 302;
        location = "http://169.254.169.254/latest/meta-data/";
        body = new byte[0];
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());

        final Response response = fetcher.get("http://127.0.0.1:" + port() + "/x", Map.of(), LIMITS);

        assertThat(response.status()).isEqualTo(302);
        assertThat(response.location()).isEqualTo(location);
        assertThat(hits).hasValue(1);
    }

    @Test
    void aDeclaredLengthOverTheCapIsRefused() {
        body = new byte[2048];
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());

        assertThatThrownBy(() -> fetcher.get("http://127.0.0.1:" + port() + "/x", Map.of(), LIMITS))
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.TOO_LARGE));
    }

    @Test
    void aChunkedBodyOverTheCapIsRefused() {
        body = new byte[4096];
        chunked = true;
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());

        assertThatThrownBy(() -> fetcher.get("http://127.0.0.1:" + port() + "/x", Map.of(), LIMITS))
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.TOO_LARGE));
    }

    @Test
    void aChunkedBodyWithinTheCapIsRead() throws Exception {
        body = "chunked body".getBytes(StandardCharsets.US_ASCII);
        chunked = true;
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());

        assertThat(fetcher.get("http://127.0.0.1:" + port() + "/x", Map.of(), LIMITS).body()).isEqualTo(body);
    }

    @Test
    void postSendsTheBody() throws Exception {
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());

        final Response response = fetcher.post("http://127.0.0.1:" + port() + "/ocsp",
                Map.of("Content-Type", "application/ocsp-request"), new byte[] {1, 2, 3}, LIMITS);

        assertThat(response.status()).isEqualTo(200);
        assertThat(hits).hasValue(1);
    }

    @Test
    void aClosedPortIsAnIoFailure() throws Exception {
        final int closed;
        try (java.net.ServerSocket s = new java.net.ServerSocket(0)) {
            closed = s.getLocalPort();
        }
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());

        assertThatThrownBy(() -> fetcher.get("http://127.0.0.1:" + closed + "/x", Map.of(), LIMITS))
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.IO));
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void theConcurrencyCapBoundsInFlightFetchesEvenWhenDnsHangs() throws Exception {
        final AtomicInteger inResolver = new AtomicInteger();
        final AtomicInteger maxInResolver = new AtomicInteger();
        final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        final OutboundUrlGuard hanging = guard("hang.test", host -> {
            maxInResolver.accumulateAndGet(inResolver.incrementAndGet(), Math::max);
            // like a native getaddrinfo: deaf to interrupts
            final long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (release.getCount() > 0 && System.nanoTime() < until) {
                try {
                    release.await(50, TimeUnit.MILLISECONDS);
                } catch (final InterruptedException e) {
                    // ignored on purpose
                }
            }
            inResolver.decrementAndGet();
            throw new UnknownHostException(host);
        });
        final FetchLimiter limiter = new FetchLimiter(2);
        final PinnedHttpFetcher fetcher = new PinnedHttpFetcher(hanging, javax.net.ssl.SSLContext.getDefault(),
                limiter);
        final Limits shortLimits = new Limits(Duration.ofSeconds(1), Duration.ofMillis(500), 1024);
        final java.util.concurrent.ExecutorService callers = java.util.concurrent.Executors.newFixedThreadPool(6);
        try {
            final List<java.util.concurrent.Future<?>> calls = new java.util.ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(callers.submit(() -> {
                    try {
                        fetcher.get("http://hang.test:" + port() + "/x", Map.of(), shortLimits);
                    } catch (final FetchException e) {
                        assertThat(e.kind()).isEqualTo(FetchException.Kind.TIMEOUT);
                    }
                    return null;
                }));
            }
            for (final var c : calls) {
                c.get(10, TimeUnit.SECONDS);
            }
            // every caller gave up at its deadline, but no more than two lookups ever ran, and they still hold the
            // two permits: a new fetch cannot start another thread
            assertThat(maxInResolver).hasValue(2);
            assertThat(limiter.inFlight()).isEqualTo(2);
            assertThatThrownBy(() -> fetcher.get("http://hang.test:" + port() + "/x", Map.of(), shortLimits))
                    .isInstanceOfSatisfying(FetchException.class,
                            e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.TIMEOUT));
            assertThat(maxInResolver).hasValue(2);
        } finally {
            release.countDown();
            callers.shutdownNow();
        }
        // once the hung lookups return, the permits come back
        final long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (limiter.inFlight() > 0 && System.nanoTime() < until) {
            Thread.sleep(20);
        }
        assertThat(limiter.inFlight()).isZero();
    }

    @Test
    void theLimiterCanBeResized() {
        final FetchLimiter limiter = new FetchLimiter(16);
        limiter.setMax(4);
        assertThat(limiter.max()).isEqualTo(4);
        assertThatThrownBy(() -> limiter.setMax(0)).isInstanceOf(IllegalArgumentException.class);
        assertThat(FetchLimiter.global().max()).isEqualTo(FetchLimiter.DEFAULT_MAX);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void singleFlightSharesOneCallBetweenConcurrentCallers() throws Exception {
        final SingleFlight<String, Integer> flight = new SingleFlight<>();
        final AtomicInteger calls = new AtomicInteger();
        final java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        try {
            final List<java.util.concurrent.Future<Integer>> results = new java.util.ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> {
                    go.await();
                    return flight.run("k", Duration.ofSeconds(5), () -> {
                        calls.incrementAndGet();
                        Thread.sleep(300);
                        return 42;
                    });
                }));
            }
            go.countDown();
            for (final var r : results) {
                assertThat(r.get(10, TimeUnit.SECONDS)).isEqualTo(42);
            }
            assertThat(calls).hasValue(1);
            // after completion the next call runs again
            assertThat(flight.run("k", Duration.ofSeconds(5), () -> calls.incrementAndGet())).isEqualTo(2);
        } finally {
            pool.shutdownNow();
        }
    }

    // ------------------------------------------------------------------------------------------- strict parsing

    /** A one-shot raw server: answers every connection with {@code response} and closes. */
    private static int raw(final String response) throws Exception {
        final java.net.ServerSocket ss = new java.net.ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        final Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (java.net.Socket s = ss.accept()) {
                    final java.io.InputStream in = s.getInputStream();
                    int st = 0;
                    int c;
                    while (st < 4 && (c = in.read()) >= 0) {
                        st = (c == '\r' && (st == 0 || st == 2)) || (c == '\n' && (st == 1 || st == 3)) ? st + 1
                                : c == '\r' ? 1 : 0;
                    }
                    s.getOutputStream().write(response.getBytes(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().flush();
                } catch (final java.io.IOException e) {
                    return;
                }
            }
        }, "raw-http");
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 5, 2\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\nhello",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n 5\r\nhello\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFFFF\r\n",
        "HTTP/1.1 +200 OK\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 20 OK\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nContent-Length\t: 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n  folded\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nbad\r\n\r\nhi",
        "HTTP/1.1 101 Switching Protocols\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\nContent-Length: 2\n\nhi",
        "hello world"})
    void aMalformedResponseIsAProtocolFailure(final String response) throws Exception {
        final int p = raw(response.replace("\\r", "\r").replace("\\n", "\n").replace("\\t", "\t"));
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());
        assertThatThrownBy(() -> fetcher.get("http://127.0.0.1:" + p + "/x", Map.of(), LIMITS)).as(response)
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.PROTOCOL));
    }

    @Test
    void identicalDuplicateContentLengthsAreAccepted() throws Exception {
        final int p = raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello");
        assertThat(PinnedHttpFetcher.plain(OutboundUrlGuard.permissive())
                .get("http://127.0.0.1:" + p + "/x", Map.of(), LIMITS).body())
                .isEqualTo("hello".getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void aNonAsciiPathIsPercentEncodedNotReplaced() throws Exception {
        final List<String> paths = new CopyOnWriteArrayList<>();
        server.createContext("/caf", exchange -> {
            try (exchange) {
                paths.add(exchange.getRequestURI().getRawPath() + "?" + exchange.getRequestURI().getRawQuery());
                exchange.sendResponseHeaders(204, -1);
            }
        });
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive());
        fetcher.get("http://127.0.0.1:" + port() + "/caf\u00e9/l\u00efst?q=\u00fc", Map.of(), LIMITS);
        assertThat(paths).containsExactly("/caf%C3%A9/l%C3%AFst?q=%C3%BC");
    }

    @Test
    void invalidRequestHeadersAreRefusedBeforeAnyConnection() {
        final AtomicInteger lookups = new AtomicInteger();
        final PinnedHttpFetcher fetcher = PinnedHttpFetcher.plain(guard("hdr.test", host -> {
            lookups.incrementAndGet();
            return new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})};
        }));
        final String url = "http://hdr.test:" + port() + "/x";
        assertThatThrownBy(() -> fetcher.get(url, Map.of("X-A", "a\r\nX-Injected: y"), LIMITS))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> fetcher.get(url, Map.of("X A", "v"), LIMITS))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> fetcher.post(url, Map.of("X-\u00e9", "v"), new byte[0], LIMITS))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(lookups).hasValue(0);
        assertThat(hits).hasValue(0);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void aStalledTlsBodyIsAbandonedAtTheDeadline() throws Exception {
        final io.helixiam.testsupport.TestTls tls = io.helixiam.testsupport.TestTls.create("stall");
        try (java.net.ServerSocket raw = tls.serverContext().getServerSocketFactory()
                .createServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))) {
            final Thread t = new Thread(() -> {
                while (!raw.isClosed()) {
                    try (java.net.Socket s = raw.accept()) {
                        final java.io.InputStream in = s.getInputStream();
                        int st = 0;
                        int c;
                        while (st < 4 && (c = in.read()) >= 0) {
                            st = (c == '\r' && (st == 0 || st == 2)) || (c == '\n' && (st == 1 || st == 3)) ? st + 1
                                    : c == '\r' ? 1 : 0;
                        }
                        s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 65\r\n\r\n0123456789"
                                .getBytes(StandardCharsets.US_ASCII));
                        s.getOutputStream().flush();
                        Thread.sleep(8_000);
                    } catch (final Exception e) {
                        // next
                    }
                }
            }, "tls-stall");
            t.setDaemon(true);
            t.start();
            final PinnedHttpFetcher fetcher = new PinnedHttpFetcher(OutboundUrlGuard.permissive(),
                    io.helixiam.authorization.messaging.email.TlsTrust.context(tls.caPem()));
            for (int i = 0; i < 3; i++) {
                final long start = System.nanoTime();
                assertThatThrownBy(() -> fetcher.get("https://localhost:" + raw.getLocalPort() + "/x", Map.of(),
                        new Limits(Duration.ofSeconds(1), Duration.ofSeconds(1), 1024)))
                        .isInstanceOfSatisfying(FetchException.class,
                                e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.TIMEOUT));
                assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1_800));
            }
        }
    }

    @Test
    void aRedirectsBodyIsNeverRead() throws Exception {
        final int p = raw("HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 5000000\r\n\r\nxxxx");
        final Response r = PinnedHttpFetcher.plain(OutboundUrlGuard.permissive()).exchange(new PinnedHttpFetcher.Request(
                "GET", "http://127.0.0.1:" + p + "/x", Map.of(), null, LIMITS, true));
        assertThat(r.status()).isEqualTo(302);
        assertThat(r.location()).isEqualTo("/next");
        assertThat(r.body()).isEmpty();
    }

    @Test
    void duplicateLocationHeadersAreAProtocolFailure() throws Exception {
        final int p = raw("HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: http://169.254.169.254/\r\n"
                + "Content-Length: 0\r\n\r\n");
        assertThatThrownBy(() -> PinnedHttpFetcher.plain(OutboundUrlGuard.permissive())
                .get("http://127.0.0.1:" + p + "/x", Map.of(), LIMITS))
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.PROTOCOL));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
        "HTTP/1.1 200 OK\r\nX-A: a\u0000b\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nX-A: a\rb\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 200 OK\r\nX-A: a\nX-B: b\r\nContent-Length: 2\r\n\r\nhi",
        "HTTP/1.1 200 O\u0000K\r\nContent-Length: 2\r\n\r\nhi"})
    void nulAndBareCrOrLfInAResponseHeadAreAProtocolFailure(final String response) throws Exception {
        final int p = raw(response);
        assertThatThrownBy(() -> PinnedHttpFetcher.plain(OutboundUrlGuard.permissive())
                .get("http://127.0.0.1:" + p + "/x", Map.of(), LIMITS)).as(response)
                .isInstanceOfSatisfying(FetchException.class,
                        e -> assertThat(e.kind()).isEqualTo(FetchException.Kind.PROTOCOL));
    }
}
