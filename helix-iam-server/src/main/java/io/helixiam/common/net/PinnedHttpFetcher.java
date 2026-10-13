/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A small HTTP/1.1 client for server-initiated fetches of attacker-influenced URLs (wallet issuer CRL / OCSP, Token
 * Status Lists) that closes the gaps the JDK clients leave:
 * <ul>
 *   <li><b>One resolution, pinned connection (DNS rebinding / TOCTOU).</b> {@link OutboundUrlGuard#resolveAllowed}
 *       resolves the host once and checks every address; the socket is then connected to one of those
 *       {@link InetAddress}es ({@code new InetSocketAddress(validatedAddress, port)}), never to the host name, so no
 *       second resolution can happen. The JDK {@code HttpClient} has no pluggable resolver and resolves again itself,
 *       hence a socket-level client. The HTTP {@code Host} header is the original host; for {@code https} the TLS
 *       socket is layered over the pinned socket with the original host as SNI and as the name the certificate is
 *       verified against (endpoint identification {@code HTTPS}).</li>
 *   <li><b>Deadline including DNS.</b> Resolution, connect, TLS handshake, request and response all run in one task
 *       the caller waits for at most {@link Limits#totalTimeout()}; at the deadline the socket is closed and the
 *       caller gets {@link FetchException.Kind#TIMEOUT}. A resolution that completes after the deadline never
 *       connects. Each connect attempt is also bounded by {@link Limits#connectTimeout()}.</li>
 *   <li><b>No redirects.</b> A 3xx answer is returned as is (with its {@code Location}); a caller that follows it
 *       must vet the target and fetch it again, which re-runs the guard.</li>
 *   <li><b>Concurrency cap.</b> At most {@link FetchLimiter#max()} fetches run at once (worker threads included,
 *       so a DNS lookup that hangs past the deadline still counts); a caller that gets no slot before its deadline
 *       times out.</li>
 *   <li><b>Size cap.</b> A declared {@code Content-Length} over {@link Limits#maxBodyBytes()} is refused before
 *       reading; a chunked or unframed body is refused as soon as it passes the cap. Headers are capped at
 *       {@value #MAX_HEADER_BYTES} bytes.</li>
 * </ul>
 * Only a 200 answer has its body read; any other status is returned with an empty body. {@code Connection: close}
 * is sent on every request, so one connection serves one request.
 */
public final class PinnedHttpFetcher {

    /** Largest response head (status line and headers) read. */
    static final int MAX_HEADER_BYTES = 32 * 1024;
    private static final int MAX_INTERIM_RESPONSES = 5;
    private static final java.util.regex.Pattern HEADER_NAME =
            java.util.regex.Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
    private static final java.util.regex.Pattern DIGITS = java.util.regex.Pattern.compile("[0-9]+");
    private static final java.util.regex.Pattern HEX = java.util.regex.Pattern.compile("[0-9A-Fa-f]{1,15}");
    private static final java.util.regex.Pattern STATUS = java.util.regex.Pattern.compile("[0-9]{3}");
    private static final java.util.regex.Pattern HTTP_VERSION = java.util.regex.Pattern.compile("HTTP/1\\.[01]");
    private static final ExecutorService WORKERS = Executors.newThreadPerTaskExecutor(
            Thread.ofVirtual().name("pinned-fetch-", 0).factory());

    /**
     * Bounds of one fetch.
     *
     * @param connectTimeout bound of each TCP connect attempt
     * @param totalTimeout   bound of the whole fetch: DNS, connect, TLS, request and the full response
     * @param maxBodyBytes   largest body accepted
     */
    public record Limits(Duration connectTimeout, Duration totalTimeout, long maxBodyBytes) {
        public Limits {
            Objects.requireNonNull(connectTimeout, "connectTimeout");
            Objects.requireNonNull(totalTimeout, "totalTimeout");
            if (connectTimeout.isNegative() || connectTimeout.isZero() || totalTimeout.isNegative()
                    || totalTimeout.isZero() || maxBodyBytes < 0) {
                throw new IllegalArgumentException("fetch limits must be positive");
            }
        }

        /** The same limits with another total timeout. */
        public Limits withTotalTimeout(final Duration value) {
            return new Limits(connectTimeout, value, maxBodyBytes);
        }
    }

    /**
     * An answer: the status, the {@code Location} header (3xx), the {@code Content-Type} header, and the body (200
     * only; empty otherwise).
     */
    public record Response(int status, String location, String contentType, byte[] body) {
    }

    /** A fetch that did not produce an answer. The message is safe to log (no URL, no peer data). */
    public static final class FetchException extends IOException {

        /** Why. */
        public enum Kind {
            /** The total deadline passed (DNS, connect, TLS or response). */
            TIMEOUT,
            /** Connect, TLS or read error, or a malformed response. */
            IO,
            /** The body is larger than the limit. */
            TOO_LARGE,
            /** The answer is not well-formed HTTP/1.1 (ambiguous framing, bad status line or header). */
            PROTOCOL
        }

        private final Kind kind;

        public FetchException(final Kind kind, final String message) {
            super(message, null);
            this.kind = Objects.requireNonNull(kind, "kind");
        }

        public Kind kind() {
            return kind;
        }
    }

    private final OutboundUrlGuard guard;
    private final SSLContext sslContext;
    private final FetchLimiter limiter;

    /** A fetcher under the {@linkplain FetchLimiter#global() global} concurrency cap. */
    public PinnedHttpFetcher(final OutboundUrlGuard guard, final SSLContext sslContext) {
        this(guard, sslContext, FetchLimiter.global());
    }

    public PinnedHttpFetcher(final OutboundUrlGuard guard, final SSLContext sslContext, final FetchLimiter limiter) {
        this.guard = Objects.requireNonNull(guard, "guard");
        this.sslContext = Objects.requireNonNull(sslContext, "sslContext");
        this.limiter = Objects.requireNonNull(limiter, "limiter");
    }

    /** A fetcher using the JDK default TLS context. */
    public static PinnedHttpFetcher plain(final OutboundUrlGuard guard) {
        try {
            return new PinnedHttpFetcher(guard, SSLContext.getDefault());
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("No default TLS context", e);
        }
    }

    /**
     * GETs {@code url}.
     *
     * @throws SsrfBlockedException the guard refused the URL (subtype {@link UnresolvableHostException}: the host did
     *                              not resolve); nothing was connected
     * @throws FetchException       no answer within the limits
     */
    public Response get(final String url, final Map<String, String> headers, final Limits limits)
            throws FetchException {
        return send("GET", url, headers, null, limits);
    }

    /** POSTs {@code body} to {@code url}; failures as for {@link #get}. */
    public Response post(final String url, final Map<String, String> headers, final byte[] body, final Limits limits)
            throws FetchException {
        return send("POST", url, headers, Objects.requireNonNull(body, "body"), limits);
    }

    private Response send(final String method, final String url, final Map<String, String> headers,
            final byte[] body, final Limits limits) throws FetchException {
        Objects.requireNonNull(limits, "limits");
        final long deadline = System.nanoTime() + limits.totalTimeout().toNanos();
        final Exchange exchange = new Exchange(method, url, headers == null ? Map.of() : headers, body, limits,
                deadline);
        try {
            if (!limiter.acquire(deadline)) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out waiting for a free slot");
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new FetchException(FetchException.Kind.IO, "fetch was interrupted");
        }
        final Future<Response> future;
        try {
            // the permit goes back when the worker ends, not when this caller stops waiting (see FetchLimiter)
            future = WORKERS.submit(() -> {
                try {
                    return exchange.run();
                } finally {
                    limiter.release();
                }
            });
        } catch (final RuntimeException e) {
            limiter.release();
            throw new FetchException(FetchException.Kind.IO, "fetch could not start");
        }
        try {
            return future.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (final TimeoutException e) {
            exchange.abort();
            future.cancel(true);
            throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
        } catch (final InterruptedException e) {
            exchange.abort();
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new FetchException(FetchException.Kind.IO, "fetch was interrupted");
        } catch (final ExecutionException e) {
            final Throwable cause = e.getCause();
            if (cause instanceof SsrfBlockedException blocked) {
                throw blocked;
            }
            if (cause instanceof FetchException fetch) {
                throw fetch;
            }
            if (exchange.timedOut()) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
            }
            throw new FetchException(FetchException.Kind.IO, "fetch failed");
        }
    }

    /** One request on one pinned connection; runs on a worker, aborted from the caller at the deadline. */
    private final class Exchange {
        private final String method;
        private final String url;
        private final Map<String, String> headers;
        private final byte[] body;
        private final Limits limits;
        private final long deadline;
        private final AtomicBoolean aborted = new AtomicBoolean();
        private final AtomicReference<Socket> socket = new AtomicReference<>();

        Exchange(final String method, final String url, final Map<String, String> headers, final byte[] body,
                final Limits limits, final long deadline) {
            this.method = method;
            this.url = url;
            this.headers = headers;
            this.body = body;
            this.limits = limits;
            this.deadline = deadline;
        }

        boolean timedOut() {
            return aborted.get() || System.nanoTime() - deadline >= 0;
        }

        void abort() {
            aborted.set(true);
            closeQuietly(socket.get());
        }

        Response run() throws IOException {
            // DNS happens here, inside the deadline: the caller stops waiting at the deadline even if the resolver
            // does not return, and a late answer is never connected to (aborted is checked below).
            final OutboundUrlGuard.ResolvedTarget target = guard.resolveAllowed(url);
            final Socket connected = connect(target);
            try {
                final Socket s = target.https() ? tls(connected, target) : connected;
                socket.set(s);
                s.setSoTimeout(remainingMillis());
                writeRequest(s.getOutputStream(), target);
                return readResponse(new DeadlineInputStream(s.getInputStream(), s));
            } catch (final SocketTimeoutException e) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
            } finally {
                closeQuietly(socket.get());
                closeQuietly(connected);
            }
        }

        /** Connects to the first validated address that accepts, each attempt bounded by the connect timeout. */
        private Socket connect(final OutboundUrlGuard.ResolvedTarget target) throws IOException {
            for (final InetAddress address : target.addresses()) {
                if (aborted.get()) {
                    break;
                }
                final int remaining = remainingMillis();
                final Socket s = new Socket();
                socket.set(s);
                try {
                    s.connect(new InetSocketAddress(address, target.port()),
                            (int) Math.min(limits.connectTimeout().toMillis(), remaining));
                    if (aborted.get()) {
                        break;
                    }
                    return s;
                } catch (final IOException e) {
                    closeQuietly(s);
                }
            }
            if (aborted.get() || System.nanoTime() - deadline >= 0) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
            }
            throw new FetchException(FetchException.Kind.IO, "could not connect");
        }

        /** TLS over the pinned socket: SNI and certificate check against the original host name. */
        private Socket tls(final Socket plain, final OutboundUrlGuard.ResolvedTarget target) throws IOException {
            final SSLSocket s = (SSLSocket) sslContext.getSocketFactory().createSocket(plain, target.host(),
                    target.port(), true);
            socket.set(s);
            final SSLParameters params = s.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            if (!isIpLiteral(target.host())) {
                try {
                    params.setServerNames(java.util.List.of(new SNIHostName(target.host())));
                } catch (final IllegalArgumentException e) {
                    // not a valid SNI name (e.g. single label): the certificate is still checked against the host
                }
            }
            params.setApplicationProtocols(new String[] {"http/1.1"});
            s.setSSLParameters(params);
            s.setSoTimeout(remainingMillis());
            try {
                s.startHandshake();
            } catch (final SocketTimeoutException e) {
                throw e;
            } catch (final IOException e) {
                throw new FetchException(FetchException.Kind.IO, "TLS handshake failed");
            }
            return s;
        }

        private void writeRequest(final OutputStream out, final OutboundUrlGuard.ResolvedTarget target)
                throws IOException {
            final String path = target.uri().getRawPath() == null || target.uri().getRawPath().isEmpty() ? "/"
                    : target.uri().getRawPath();
            final String query = target.uri().getRawQuery() == null ? "" : "?" + target.uri().getRawQuery();
            final StringBuilder head = new StringBuilder(256)
                    .append(method).append(' ').append(path).append(query).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(hostHeader(target)).append("\r\n")
                    .append("User-Agent: HelixIAM\r\n")
                    .append("Connection: close\r\n");
            for (final Map.Entry<String, String> h : headers.entrySet()) {
                head.append(token(h.getKey())).append(": ").append(value(h.getValue())).append("\r\n");
            }
            if (body != null) {
                head.append("Content-Length: ").append(body.length).append("\r\n");
            }
            head.append("\r\n");
            out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
            if (body != null) {
                out.write(body);
            }
            out.flush();
        }

        private Response readResponse(final InputStream in) throws IOException {
            for (int interim = 0; interim <= MAX_INTERIM_RESPONSES; interim++) {
                final String head = readHead(in);
                final String[] lines = head.split("\r\n", -1);
                final int status = statusCode(lines[0]);
                final Map<String, java.util.List<String>> fields = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                for (int i = 1; i < lines.length; i++) {
                    final String line = lines[i];
                    final int colon = line.indexOf(':');
                    // no obs-fold continuation lines, no whitespace before the colon (RFC 9112 5.1, 5.2)
                    if (colon <= 0 || !HEADER_NAME.matcher(line.substring(0, colon)).matches()) {
                        throw malformed("malformed response header");
                    }
                    fields.computeIfAbsent(line.substring(0, colon), k -> new java.util.ArrayList<>())
                            .add(line.substring(colon + 1).trim());
                }
                if (status >= 100 && status < 200) {
                    continue; // interim answer (100 Continue): the real one follows
                }
                final String location = first(fields, "Location");
                final String contentType = first(fields, "Content-Type");
                if (status != 200) {
                    return new Response(status, location, contentType, new byte[0]);
                }
                return new Response(status, location, contentType, readBody(in, fields));
            }
            throw malformed("too many interim responses");
        }

        private byte[] readBody(final InputStream in, final Map<String, java.util.List<String>> fields)
                throws IOException {
            final long max = limits.maxBodyBytes();
            final java.util.List<String> te = fields.get("Transfer-Encoding");
            final java.util.List<String> cl = fields.get("Content-Length");
            if (te != null && cl != null) {
                throw malformed("both Content-Length and Transfer-Encoding"); // ambiguous framing
            }
            if (te != null) {
                if (te.size() != 1 || !"chunked".equalsIgnoreCase(te.get(0))) {
                    throw malformed("unsupported transfer encoding");
                }
                return readChunked(in, max);
            }
            if (cl != null) {
                long declared = -1;
                for (final String v : cl) {
                    // digits only (no sign, no list), and every repetition the same value
                    if (!DIGITS.matcher(v).matches() || v.length() > 18) {
                        throw malformed("malformed content length");
                    }
                    final long value = Long.parseLong(v);
                    if (declared >= 0 && value != declared) {
                        throw malformed("conflicting content lengths");
                    }
                    declared = value;
                }
                if (declared > max) {
                    throw new FetchException(FetchException.Kind.TOO_LARGE, "response body too large");
                }
                final byte[] out = in.readNBytes((int) declared);
                if (out.length != declared) {
                    throw new FetchException(FetchException.Kind.IO, "response body truncated");
                }
                return out;
            }
            final byte[] out = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, max + 1));
            if (out.length > max) {
                throw new FetchException(FetchException.Kind.TOO_LARGE, "response body too large");
            }
            return out;
        }

        private byte[] readChunked(final InputStream in, final long max) throws IOException {
            final ByteArrayOutputStream out = new ByteArrayOutputStream();
            while (true) {
                final String sizeLine = readLine(in);
                final int semi = sizeLine.indexOf(';');
                final String hex = semi >= 0 ? sizeLine.substring(0, semi) : sizeLine;
                // hex digits only: no sign, no whitespace, at most 15 digits (fits a long)
                if (!HEX.matcher(hex).matches()) {
                    throw malformed("malformed chunk size");
                }
                final long size = Long.parseLong(hex, 16);
                if (size == 0) {
                    // trailers, up to the empty line
                    int trailers = 0;
                    while (!readLine(in).isEmpty()) {
                        if (++trailers > 64) {
                            throw malformed("too many trailers");
                        }
                    }
                    return out.toByteArray();
                }
                if (out.size() + size > max) {
                    throw new FetchException(FetchException.Kind.TOO_LARGE, "response body too large");
                }
                final byte[] chunk = in.readNBytes((int) size);
                if (chunk.length != size) {
                    throw new FetchException(FetchException.Kind.IO, "response body truncated");
                }
                out.write(chunk);
                if (!readLine(in).isEmpty()) {
                    throw malformed("malformed chunk");
                }
            }
        }

        private int remainingMillis() throws FetchException {
            final long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
            if (remaining <= 0 || aborted.get()) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
            }
            return (int) Math.min(Integer.MAX_VALUE, remaining);
        }

        /** Re-arms the socket read timeout to the time left before every read, so no read outlives the deadline. */
        private final class DeadlineInputStream extends InputStream {
            private final InputStream in;
            private final Socket s;

            DeadlineInputStream(final InputStream in, final Socket s) {
                this.in = in;
                this.s = s;
            }

            @Override
            public int read() throws IOException {
                s.setSoTimeout(remainingMillis());
                return in.read();
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                s.setSoTimeout(remainingMillis());
                return in.read(b, off, len);
            }
        }
    }

    /** The status line, then header lines, up to the empty line; at most {@value #MAX_HEADER_BYTES} bytes. */
    private static String readHead(final InputStream in) throws IOException {
        final ByteArrayOutputStream head = new ByteArrayOutputStream(512);
        int state = 0; // matched bytes of \r\n\r\n
        while (state < 4) {
            final int b = in.read();
            if (b < 0) {
                throw new FetchException(FetchException.Kind.IO, "connection closed before the response");
            }
            head.write(b);
            if (head.size() > MAX_HEADER_BYTES) {
                throw malformed("response headers too large");
            }
            state = (b == '\r' && (state == 0 || state == 2)) || (b == '\n' && (state == 1 || state == 3))
                    ? state + 1 : b == '\r' ? 1 : 0;
        }
        final String text = head.toString(StandardCharsets.ISO_8859_1);
        return text.substring(0, text.length() - 4);
    }

    /** One CRLF-terminated line (chunk sizes, trailers); at most 4 KB. */
    private static String readLine(final InputStream in) throws IOException {
        final StringBuilder line = new StringBuilder(16);
        while (true) {
            final int b = in.read();
            if (b < 0) {
                throw new FetchException(FetchException.Kind.IO, "response body truncated");
            }
            if (b == '\n') {
                final int end = line.length();
                return end > 0 && line.charAt(end - 1) == '\r' ? line.substring(0, end - 1) : line.toString();
            }
            line.append((char) b);
            if (line.length() > 4096) {
                throw malformed("malformed chunk");
            }
        }
    }

    private static int statusCode(final String statusLine) throws FetchException {
        final String[] parts = statusLine.split(" ", 3);
        // HTTP/1.x, then exactly three digits (RFC 9112 4)
        if (parts.length < 2 || !HTTP_VERSION.matcher(parts[0]).matches() || !STATUS.matcher(parts[1]).matches()) {
            throw malformed("malformed status line");
        }
        return Integer.parseInt(parts[1]);
    }

    private static String first(final Map<String, java.util.List<String>> fields, final String name) {
        final java.util.List<String> values = fields.get(name);
        return values == null ? null : values.get(0);
    }

    private static FetchException malformed(final String message) {
        return new FetchException(FetchException.Kind.PROTOCOL, message);
    }

    private static String hostHeader(final OutboundUrlGuard.ResolvedTarget target) {
        final String host = target.host().indexOf(':') >= 0 ? "[" + target.host() + "]" : target.host();
        final int defaultPort = target.https() ? 443 : 80;
        return target.uri().getPort() < 0 || target.port() == defaultPort ? host : host + ":" + target.port();
    }

    private static boolean isIpLiteral(final String host) {
        return host.indexOf(':') >= 0 || host.matches("[0-9.]+");
    }

    /** A header name from a caller: a token, never CR/LF. */
    private static String token(final String name) {
        if (name == null || !name.matches("[A-Za-z0-9-]+")) {
            throw new IllegalArgumentException("invalid header name");
        }
        return name;
    }

    /** A header value from a caller: printable ASCII only. */
    private static String value(final String v) {
        if (v == null || !v.matches("[\\x20-\\x7E]*")) {
            throw new IllegalArgumentException("invalid header value");
        }
        return v;
    }

    private static void closeQuietly(final Socket s) {
        if (s == null) {
            return;
        }
        try {
            s.close();
        } catch (final IOException e) {
            // nothing to do
        }
    }

    /** Lower-cased media type without parameters, or null. */
    public static String mediaType(final String contentType) {
        if (contentType == null) {
            return null;
        }
        final int semi = contentType.indexOf(';');
        return (semi >= 0 ? contentType.substring(0, semi) : contentType).trim().toLowerCase(Locale.ROOT);
    }
}
