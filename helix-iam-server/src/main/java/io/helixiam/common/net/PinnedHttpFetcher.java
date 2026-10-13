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
    /** Most bytes of an error (non-2xx) body read; more is truncated, never a failure. */
    static final int ERROR_BODY_BYTES = 16 * 1024;

    /** A body and whether it was cut short. */
    private record Body(byte[] bytes, boolean truncated) {
    }
    private static final java.util.Set<String> METHODS = java.util.Set.of("GET", "HEAD", "POST", "PUT", "PATCH",
            "DELETE", "OPTIONS");
    private static final java.util.Set<String> BODY_METHODS = java.util.Set.of("POST", "PUT", "PATCH");
    private static final java.util.Set<String> RESTRICTED_HEADERS = java.util.Set.of("host", "connection",
            "content-length", "transfer-encoding", "expect", "upgrade", "te", "keep-alive", "proxy-connection");
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
     * @param readTimeout    longest wait for each read (TLS handshake and response), or null for the total only
     */
    public record Limits(Duration connectTimeout, Duration totalTimeout, long maxBodyBytes, Duration readTimeout) {
        public Limits {
            Objects.requireNonNull(connectTimeout, "connectTimeout");
            Objects.requireNonNull(totalTimeout, "totalTimeout");
            if (connectTimeout.isNegative() || connectTimeout.isZero() || totalTimeout.isNegative()
                    || totalTimeout.isZero() || maxBodyBytes < 0
                    || readTimeout != null && (readTimeout.isNegative() || readTimeout.isZero())) {
                throw new IllegalArgumentException("fetch limits must be positive");
            }
        }

        /** No limit between reads other than the total. */
        public Limits(final Duration connectTimeout, final Duration totalTimeout, final long maxBodyBytes) {
            this(connectTimeout, totalTimeout, maxBodyBytes, null);
        }

        /** The same limits with another total timeout. */
        public Limits withTotalTimeout(final Duration value) {
            return new Limits(connectTimeout, value, maxBodyBytes, readTimeout);
        }
    }

    /**
     * An answer: the status, the {@code Location} header (3xx), the {@code Content-Type} header, and the body (200
     * only; empty otherwise).
     */
    public record Response(int status, String location, String contentType, byte[] body,
            Map<String, java.util.List<String>> headers, boolean truncated) {

        /** A complete body. */
        public Response(final int status, final String location, final String contentType, final byte[] body,
                final Map<String, java.util.List<String>> headers) {
            this(status, location, contentType, body, headers, false);
        }

        public Response {
            final Map<String, java.util.List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            if (headers != null) {
                headers.forEach((k, v) -> copy.put(k, java.util.List.copyOf(v)));
            }
            headers = java.util.Collections.unmodifiableMap(copy);
        }

        /** The first value of response header {@code name} (case-insensitive), or null. */
        public String header(final String name) {
            final java.util.List<String> values = headers.get(name);
            return values == null || values.isEmpty() ? null : values.get(0);
        }

        /** The body as text in the {@code charset} of its Content-Type, UTF-8 when absent or unknown. */
        public String bodyAsString() {
            java.nio.charset.Charset charset = StandardCharsets.UTF_8;
            if (contentType != null) {
                for (final String param : contentType.split(";")) {
                    final String p = param.trim();
                    if (p.regionMatches(true, 0, "charset=", 0, 8)) {
                        try {
                            charset = java.nio.charset.Charset.forName(p.substring(8).replace("\"", "").trim());
                        } catch (final RuntimeException e) {
                            charset = StandardCharsets.UTF_8;
                        }
                    }
                }
            }
            return new String(body, charset);
        }
    }

    /**
     * A request for {@link #exchange}.
     *
     * @param method              GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS
     * @param url                 the target (vetted by the guard, inside the deadline)
     * @param headers             request headers; Host, Connection, Content-Length, Transfer-Encoding, Expect, Upgrade,
     *                            TE and Keep-Alive are set by the client and refused here
     * @param body                the request body, or null for none
     * @param limits              connect / total timeouts and the response body cap
     * @param readBodyOfAnyStatus read the body of every final answer (error bodies included), not only of a 200
     */
    public record Request(String method, String url, Map<String, String> headers, byte[] body, Limits limits,
            boolean readBodyOfAnyStatus, String partition) {

        /** Without a partition: the fetcher's default partition applies. */
        public Request(final String method, final String url, final Map<String, String> headers, final byte[] body,
                final Limits limits, final boolean readBodyOfAnyStatus) {
            this(method, url, headers, body, limits, readBodyOfAnyStatus, null);
        }

        /** The same request in {@code value} (a realm) for the limiter's per-realm sub-cap. */
        public Request inPartition(final String value) {
            return new Request(method, url, headers, body, limits, readBodyOfAnyStatus, value);
        }
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
            PROTOCOL,
            /** The TLS handshake failed: untrusted certificate, host name mismatch, or no common protocol. */
            TLS
        }

        private final Kind kind;
        private final int status;

        public FetchException(final Kind kind, final String message) {
            this(kind, message, -1);
        }

        public FetchException(final Kind kind, final String message, final int status) {
            super(message, null);
            this.kind = Objects.requireNonNull(kind, "kind");
            this.status = status;
        }

        public Kind kind() {
            return kind;
        }

        /** The HTTP status when one was received (for {@link Kind#TOO_LARGE}), else -1. */
        public int status() {
            return status;
        }
    }

    private final OutboundUrlGuard guard;
    private final SSLContext sslContext;
    private final FetchLimiter limiter;
    private final java.util.function.Supplier<String> defaultPartition;

    /** A fetcher under the {@linkplain FetchLimiter#global() global} concurrency cap. */
    public PinnedHttpFetcher(final OutboundUrlGuard guard, final SSLContext sslContext) {
        this(guard, sslContext, FetchLimiter.global());
    }

    public PinnedHttpFetcher(final OutboundUrlGuard guard, final SSLContext sslContext, final FetchLimiter limiter) {
        this(guard, sslContext, limiter, () -> null);
    }

    /**
     * A fetcher whose slots come from {@code limiter}; {@code defaultPartition} names the partition (the realm) of a
     * request that does not name one, for the limiter's per-realm sub-cap (null: none).
     */
    public PinnedHttpFetcher(final OutboundUrlGuard guard, final SSLContext sslContext, final FetchLimiter limiter,
            final java.util.function.Supplier<String> defaultPartition) {
        this.defaultPartition = Objects.requireNonNull(defaultPartition, "defaultPartition");
        this.guard = Objects.requireNonNull(guard, "guard");
        this.sslContext = Objects.requireNonNull(sslContext, "sslContext");
        this.limiter = Objects.requireNonNull(limiter, "limiter");
    }

    /** A fetcher of feature {@code group}, using the JDK default TLS context and {@code partition} per request. */
    public static PinnedHttpFetcher plain(final OutboundUrlGuard guard, final FetchLimiter.Group group,
            final java.util.function.Supplier<String> partition) {
        try {
            return new PinnedHttpFetcher(guard, SSLContext.getDefault(), FetchLimiter.forGroup(group), partition);
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("No default TLS context", e);
        }
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
     * @throws IllegalArgumentException a header name is not a token or a value is not printable ASCII (checked
     *                              before any lookup or connection)
     */
    public Response get(final String url, final Map<String, String> headers, final Limits limits)
            throws FetchException {
        return exchange(new Request("GET", url, headers, null, limits, false));
    }

    /** POSTs {@code body} to {@code url}; failures as for {@link #get}. */
    public Response post(final String url, final Map<String, String> headers, final byte[] body, final Limits limits)
            throws FetchException {
        return exchange(new Request("POST", url, headers, Objects.requireNonNull(body, "body"), limits, false));
    }

    /** Any method, any body; failures as for {@link #get}. */
    public Response exchange(final Request request) throws FetchException {
        Objects.requireNonNull(request, "request");
        final String method = request.method();
        if (method == null || !METHODS.contains(method)) {
            throw new IllegalArgumentException("unsupported HTTP method");
        }
        final Map<String, String> headers = request.headers();
        final Limits limits = Objects.requireNonNull(request.limits(), "limits");
        final byte[] body = request.body();
        final String url = request.url();
        // the request is validated whole before any DNS lookup or connection
        if (headers != null) {
            headers.forEach((name, value) -> {
                token(name);
                value(value);
                if (RESTRICTED_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                    throw new IllegalArgumentException("restricted header " + name);
                }
            });
        }
        final long deadline = System.nanoTime() + limits.totalTimeout().toNanos();
        final String partition = request.partition() != null ? request.partition() : defaultPartition.get();
        final Exchange exchange = new Exchange(method, url, headers == null ? Map.of() : headers, body, limits,
                deadline, request.readBodyOfAnyStatus());
        try {
            if (!limiter.acquire(deadline, partition)) {
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
                    limiter.release(partition);
                }
            });
        } catch (final RuntimeException e) {
            limiter.release(partition);
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
        private final boolean readBodyOfAnyStatus;
        private final SocketSlot slot = new SocketSlot();

        Exchange(final String method, final String url, final Map<String, String> headers, final byte[] body,
                final Limits limits, final long deadline, final boolean readBodyOfAnyStatus) {
            this.readBodyOfAnyStatus = readBodyOfAnyStatus;
            this.method = method;
            this.url = url;
            this.headers = headers;
            this.body = body;
            this.limits = limits;
            this.deadline = deadline;
        }

        boolean timedOut() {
            return slot.aborted() || System.nanoTime() - deadline >= 0;
        }

        void abort() {
            slot.abort();
        }

        Response run() throws IOException {
            // DNS happens here, inside the deadline: the caller stops waiting at the deadline even if the resolver
            // does not return, and a late answer is never connected to (aborted is checked below).
            final OutboundUrlGuard.ResolvedTarget target = guard.resolveAllowed(url);
            final Socket connected = connect(target);
            try {
                final Socket s = target.https() ? tls(connected, target) : connected;
                slot.register(s);
                s.setSoTimeout(remainingMillis());
                writeRequest(s.getOutputStream(), target);
                return readResponse(new DeadlineInputStream(s.getInputStream(), s));
            } catch (final SocketTimeoutException e) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
            } finally {
                closeQuietly(slot.current());
                closeQuietly(connected);
            }
        }

        /** Connects to the first validated address that accepts, each attempt bounded by the connect timeout. */
        private Socket connect(final OutboundUrlGuard.ResolvedTarget target) throws IOException {
            for (final InetAddress address : target.addresses()) {
                if (slot.aborted()) {
                    break;
                }
                final int remaining = remainingMillis();
                final Socket s = new Socket();
                slot.register(s); // closed and refused if the caller aborted meanwhile
                try {
                    s.connect(new InetSocketAddress(address, target.port()),
                            (int) Math.min(limits.connectTimeout().toMillis(), remaining));
                    if (slot.aborted()) {
                        break;
                    }
                    return s;
                } catch (final IOException e) {
                    closeQuietly(s);
                }
            }
            if (slot.aborted() || System.nanoTime() - deadline >= 0) {
                throw new FetchException(FetchException.Kind.TIMEOUT, "fetch timed out");
            }
            throw new FetchException(FetchException.Kind.IO, "could not connect");
        }

        /** TLS over the pinned socket: SNI and certificate check against the original host name. */
        private Socket tls(final Socket plain, final OutboundUrlGuard.ResolvedTarget target) throws IOException {
            final SSLSocket s = (SSLSocket) sslContext.getSocketFactory().createSocket(plain, target.host(),
                    target.port(), true);
            slot.register(s);
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
            s.setSoTimeout(readWaitMillis());
            try {
                s.startHandshake();
            } catch (final SocketTimeoutException e) {
                throw e;
            } catch (final javax.net.ssl.SSLException e) {
                throw new FetchException(FetchException.Kind.TLS, "TLS handshake failed");
            } catch (final IOException e) {
                throw new FetchException(FetchException.Kind.IO, "connection lost during the TLS handshake");
            }
            return s;
        }

        private void writeRequest(final OutputStream out, final OutboundUrlGuard.ResolvedTarget target)
                throws IOException {
            // toASCIIString percent-encodes any non-ASCII character (UTF-8), which the raw path keeps as is
            final java.net.URI ascii = java.net.URI.create(target.uri().toASCIIString());
            final String path = ascii.getRawPath() == null || ascii.getRawPath().isEmpty() ? "/" : ascii.getRawPath();
            final String query = ascii.getRawQuery() == null ? "" : "?" + ascii.getRawQuery();
            final StringBuilder head = new StringBuilder(256)
                    .append(method).append(' ').append(path).append(query).append(" HTTP/1.1\r\n")
                    .append("Host: ").append(hostHeader(target)).append("\r\n")
                    .append("Connection: close\r\n");
            if (headers.keySet().stream().noneMatch(k -> k.equalsIgnoreCase("User-Agent"))) {
                head.append("User-Agent: HelixIAM\r\n");
            }
            for (final Map.Entry<String, String> h : headers.entrySet()) {
                head.append(token(h.getKey())).append(": ").append(value(h.getValue())).append("\r\n");
            }
            if (body != null) {
                head.append("Content-Length: ").append(body.length).append("\r\n");
            } else if (BODY_METHODS.contains(method)) {
                head.append("Content-Length: 0\r\n"); // an empty body, stated (no chunked request bodies)
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
                for (final String line : lines) {
                    // NUL, a bare CR or a bare LF inside the status line or a header: refused (RFC 9112 2.2, 5)
                    if (line.indexOf('\0') >= 0 || line.indexOf('\r') >= 0 || line.indexOf('\n') >= 0) {
                        throw malformed("control character in the response head");
                    }
                }
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
                if (status == 101) {
                    throw malformed("protocol switch refused"); // nothing here asks for an upgrade
                }
                if (status >= 100 && status < 200) {
                    continue; // interim answer (100 Continue): the real one follows
                }
                final java.util.List<String> locations = fields.get("Location");
                if (locations != null && locations.size() > 1) {
                    throw malformed("duplicate Location headers"); // which one would a client follow?
                }
                final String location = first(fields, "Location");
                final String contentType = first(fields, "Content-Type");
                // no body: HEAD, 204, 304 (RFC 9112 6.3), and a redirect's body is never read (only Location is used);
                // otherwise only a 200's unless every body is wanted
                final boolean noBody = "HEAD".equals(method) || status == 204 || status == 304 || status / 100 == 3;
                if (noBody || status != 200 && !readBodyOfAnyStatus) {
                    return new Response(status, location, contentType, new byte[0], fields);
                }
                if (status / 100 != 2) {
                    // an error body is only diagnostic: at most ERROR_BODY_BYTES, truncated, so the status is kept
                    final Body b = readBody(in, fields, status, Math.min(limits.maxBodyBytes(), ERROR_BODY_BYTES), true);
                    return new Response(status, location, contentType, b.bytes(), fields, b.truncated());
                }
                return new Response(status, location, contentType,
                        readBody(in, fields, status, limits.maxBodyBytes(), false).bytes(), fields);
            }
            throw malformed("too many interim responses");
        }

        /**
         * The body within {@code max}: over it, {@code truncate} keeps the first {@code max} bytes (and stops reading),
         * otherwise it is {@code TOO_LARGE}.
         */
        private Body readBody(final InputStream in, final Map<String, java.util.List<String>> fields,
                final int status, final long max, final boolean truncate) throws IOException {
            final java.util.List<String> te = fields.get("Transfer-Encoding");
            final java.util.List<String> cl = fields.get("Content-Length");
            if (te != null && cl != null) {
                throw malformed("both Content-Length and Transfer-Encoding"); // ambiguous framing
            }
            if (te != null) {
                if (te.size() != 1 || !"chunked".equalsIgnoreCase(te.get(0))) {
                    throw malformed("unsupported transfer encoding");
                }
                return readChunked(in, max, status, truncate);
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
                    if (!truncate) {
                        throw new FetchException(FetchException.Kind.TOO_LARGE, "response body too large", status);
                    }
                    return new Body(in.readNBytes((int) max), true);
                }
                final byte[] out = in.readNBytes((int) declared);
                if (out.length != declared) {
                    throw new FetchException(FetchException.Kind.IO, "response body truncated");
                }
                return new Body(out, false);
            }
            final byte[] out = in.readNBytes((int) Math.min(Integer.MAX_VALUE - 8, max + 1));
            if (out.length > max) {
                if (!truncate) {
                    throw new FetchException(FetchException.Kind.TOO_LARGE, "response body too large", status);
                }
                return new Body(java.util.Arrays.copyOf(out, (int) max), true);
            }
            return new Body(out, false);
        }

        private Body readChunked(final InputStream in, final long max, final int status, final boolean truncate)
                throws IOException {
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
                    return new Body(out.toByteArray(), false);
                }
                if (out.size() + size > max) {
                    if (!truncate) {
                        throw new FetchException(FetchException.Kind.TOO_LARGE, "response body too large", status);
                    }
                    out.write(in.readNBytes((int) (max - out.size())));
                    return new Body(out.toByteArray(), true);
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

        /** The time left, or the per-read limit when that is shorter. */
        private int readWaitMillis() throws FetchException {
            final int remaining = remainingMillis();
            return limits.readTimeout() == null ? remaining
                    : (int) Math.max(1, Math.min(remaining, limits.readTimeout().toMillis()));
        }

        private int remainingMillis() throws FetchException {
            final long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
            if (remaining <= 0 || slot.aborted()) {
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
                s.setSoTimeout(readWaitMillis());
                return in.read();
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                s.setSoTimeout(readWaitMillis());
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
                if (head.size() > 0) {
                    throw malformed("incomplete response head"); // not HTTP/1.1 (bare LF, HTTP/0.9, garbage)
                }
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

    /** A header name from a caller: an RFC 9110 token (never CR/LF, space or non-ASCII). */
    private static String token(final String name) {
        if (name == null || !HEADER_NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("invalid header name");
        }
        return name;
    }

    /**
     * A header value from a caller: visible ASCII, space and horizontal tab (RFC 9110 field-value). CR, LF, NUL and the
     * other control characters are refused, and so is non-ASCII (not sent by this client), each with a message that
     * says which, since it usually means a misconfigured value (a token or name pasted with a stray character).
     */
    private static String value(final String v) {
        if (v == null) {
            throw new IllegalArgumentException("invalid header value: missing");
        }
        for (int i = 0; i < v.length(); i++) {
            final char c = v.charAt(i);
            if (c > 0x7E && c != 0x7F) {
                throw new IllegalArgumentException("invalid header value: non-ASCII characters are not allowed");
            }
            if (c < 0x20 && c != '\t' || c == 0x7F) {
                throw new IllegalArgumentException("invalid header value: a control character is not allowed");
            }
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
