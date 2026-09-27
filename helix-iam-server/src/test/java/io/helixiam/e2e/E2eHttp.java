/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A tiny "browser" for the e2e harness: a {@link HttpClient} with its own cookie jar that does <b>not</b>
 * follow redirects automatically. Tests step through redirect chains one hop at a time
 * ({@link #followRedirectsUntil}) so they can inspect every {@code Location} header — e.g. to read the
 * authorization {@code code} off the redirect to the client's redirect URI without ever calling it.
 *
 * <p>One instance == one user agent (one session cookie). Use a fresh instance per simulated browser.
 * Relative paths are resolved against the server base URL; absolute URLs are used as-is.
 */
public final class E2eHttp {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_HOPS = 20;

    private final URI base;
    private final CookieManager cookies;
    private final HttpClient client;
    /** One line per exchange (method, URI, status, Location) — appended to assertion messages as a trail. */
    private final List<String> history = new ArrayList<>();

    public E2eHttp(final String baseUrl) {
        this.base = URI.create(baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
        this.cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        this.client = HttpClient.newBuilder()
                .cookieHandler(cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                // Plain HTTP/1.1: avoids an h2c upgrade attempt against the embedded Tomcat.
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    /** The server base URL, e.g. {@code http://localhost:54321/}. */
    public URI base() {
        return base;
    }

    /** Resolves a server-relative path ({@code /realms/master/login}) or passes an absolute URL through. */
    public URI resolve(final String pathOrUrl) {
        final URI uri = URI.create(pathOrUrl);
        if (uri.isAbsolute()) {
            return uri;
        }
        return base.resolve(pathOrUrl.startsWith("/") ? pathOrUrl.substring(1) : pathOrUrl);
    }

    // ------------------------------------------------------------------------------------------------
    // Requests
    // ------------------------------------------------------------------------------------------------

    /**
     * GET; {@code headers} are name/value pairs ({@code "Authorization", "Bearer …"}). Unless the caller sets
     * {@code Accept}, a browser-like {@code Accept: text/html…} is sent: the authorization-server chain only
     * redirects an unauthenticated {@code /oauth2/authorize} to the login page for HTML requests (anything else
     * gets a bare 401), exactly as a real browser navigation would.
     */
    public Response get(final String pathOrUrl, final String... headers) {
        final HttpRequest.Builder b = request(pathOrUrl, headers).GET();
        if (!hasHeader(headers, "Accept")) {
            b.header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        }
        return send(b);
    }

    private static boolean hasHeader(final String[] headers, final String name) {
        for (int i = 0; i < headers.length; i += 2) {
            if (headers[i].equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    /** POST {@code application/x-www-form-urlencoded} (single-valued fields, insertion order kept). */
    public Response postForm(final String pathOrUrl, final Map<String, String> fields, final String... headers) {
        final List<Map.Entry<String, String>> pairs = new ArrayList<>(fields.entrySet());
        return postForm(pathOrUrl, pairs, headers);
    }

    /** POST {@code application/x-www-form-urlencoded} with repeatable fields (e.g. several {@code scope}). */
    public Response postForm(final String pathOrUrl, final List<Map.Entry<String, String>> fields,
                             final String... headers) {
        final String body = fields.stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue() == null ? "" : e.getValue()))
                .collect(Collectors.joining("&"));
        return send(request(pathOrUrl, headers)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    /** Sends a JSON body with an arbitrary method (POST/PUT/PATCH); {@code json} may be a String or any POJO. */
    public Response sendJson(final String method, final String pathOrUrl, final Object json, final String... headers) {
        final String body;
        try {
            body = json instanceof String s ? s : JSON.writeValueAsString(json);
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        }
        return send(request(pathOrUrl, headers)
                .header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body)));
    }

    /**
     * POST {@code multipart/form-data}: plain {@code fields} plus one file part {@code fileField} with
     * {@code filename}, {@code contentType} and {@code content}.
     */
    public Response postMultipart(final String pathOrUrl, final Map<String, String> fields, final String fileField,
                                  final String filename, final String contentType, final byte[] content,
                                  final String... headers) {
        final String boundary = "----e2e" + Long.toHexString(System.nanoTime());
        final java.io.ByteArrayOutputStream body = new java.io.ByteArrayOutputStream();
        final java.util.function.Consumer<String> text = s -> body.writeBytes(s.getBytes(StandardCharsets.UTF_8));
        fields.forEach((k, v) -> {
            text.accept("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + k + "\"\r\n\r\n");
            text.accept(v + "\r\n");
        });
        text.accept("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + fileField + "\"; filename=\""
                + filename + "\"\r\nContent-Type: " + contentType + "\r\n\r\n");
        body.writeBytes(content);
        text.accept("\r\n--" + boundary + "--\r\n");
        return send(request(pathOrUrl, headers)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray())));
    }

    /** GET returning the raw body bytes (for binary resources). */
    public BytesResponse getBytes(final String pathOrUrl, final String... headers) {
        return sendBytes("GET", pathOrUrl, headers);
    }

    /** HEAD (the body must be empty). */
    public BytesResponse head(final String pathOrUrl, final String... headers) {
        return sendBytes("HEAD", pathOrUrl, headers);
    }

    private BytesResponse sendBytes(final String method, final String pathOrUrl, final String... headers) {
        final HttpRequest request = request(pathOrUrl, headers).method(method, HttpRequest.BodyPublishers.noBody()).build();
        try {
            final HttpResponse<byte[]> r = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
            history.add(request.method() + " " + request.uri() + " -> " + r.statusCode());
            return new BytesResponse(r.statusCode(), r.headers(), r.body());
        } catch (final IOException e) {
            throw new UncheckedIOException(request.method() + " " + request.uri() + " failed", e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    /** A binary response. */
    public record BytesResponse(int status, HttpHeaders headers, byte[] body) {
        public Optional<String> header(final String name) {
            return headers.firstValue(name);
        }
    }

    /** DELETE. */
    public Response delete(final String pathOrUrl, final String... headers) {
        return send(request(pathOrUrl, headers).DELETE());
    }

    /**
     * Follows redirects one GET hop at a time, starting at {@code start}, and returns the first response
     * that either matches {@code stop} or is not a redirect. {@code stop} is tested before each hop, so a
     * predicate like {@code r -> r.locationStartsWith(redirectUri)} returns the 302 <i>to</i> the client
     * without requesting the client URL.
     */
    public Response followRedirectsUntil(final Response start, final Predicate<Response> stop) {
        Response current = start;
        for (int hop = 0; hop < MAX_HOPS; hop++) {
            if (stop.test(current) || !current.isRedirect()) {
                return current;
            }
            current = get(current.location().toString());
        }
        throw new AssertionError("Too many redirects (>" + MAX_HOPS + "), last: " + current);
    }

    /** The last {@code n} exchanges of this browser, one per line — for assertion messages. */
    public String trail(final int n) {
        return "Recent exchanges:\n  " + String.join("\n  ", history.subList(Math.max(0, history.size() - n), history.size()));
    }

    /** Follows redirects until a non-redirect response. */
    public Response followRedirects(final Response start) {
        return followRedirectsUntil(start, r -> false);
    }

    // ------------------------------------------------------------------------------------------------
    // Cookies
    // ------------------------------------------------------------------------------------------------

    /** The value of a cookie currently in this browser's jar (any path), if present. */
    public Optional<String> cookie(final String name) {
        return cookies.getCookieStore().getCookies().stream()
                .filter(c -> c.getName().equals(name))
                .map(HttpCookie::getValue)
                .findFirst();
    }

    /**
     * The {@code XSRF-TOKEN} cookie this browser would send to {@code pathOrUrl}. The cookie's path follows the
     * request's context path, so the token under {@code /realms/{r}/…} differs from the one under {@code /admin}.
     */
    public Optional<String> cookieFor(final String name, final String pathOrUrl) {
        return cookies.getCookieStore().get(resolve(pathOrUrl)).stream()
                .filter(c -> c.getName().equals(name) && !c.getValue().isBlank())
                .map(HttpCookie::getValue)
                .findFirst();
    }

    /** The {@code X-XSRF-TOKEN} header pair echoing the {@code XSRF-TOKEN} cookie (double-submit CSRF). */
    public String[] xsrfHeader() {
        final String token = cookie("XSRF-TOKEN")
                .orElseThrow(() -> new AssertionError("No XSRF-TOKEN cookie in the jar"));
        return new String[] {"X-XSRF-TOKEN", token};
    }

    // ------------------------------------------------------------------------------------------------
    // HTML scraping (deliberately regex-based: the server-rendered pages are small and stable)
    // ------------------------------------------------------------------------------------------------

    private static final Pattern INPUT = Pattern.compile("<input\\b[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM = Pattern.compile("<form\\b([^>]*)>(.*?)</form>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /** The hidden {@code _csrf} value Thymeleaf renders into a server-side form. */
    public static String csrf(final String html) {
        final String token = hiddenInputs(html).get("_csrf");
        if (token == null) {
            throw new AssertionError("No hidden _csrf input in page:\n" + snippet(html));
        }
        return token;
    }

    /** All {@code <input type="hidden">} name→value pairs in the HTML (first occurrence wins). */
    public static Map<String, String> hiddenInputs(final String html) {
        final Map<String, String> out = new LinkedHashMap<>();
        final Matcher m = INPUT.matcher(html);
        while (m.find()) {
            final String tag = m.group();
            if ("hidden".equalsIgnoreCase(attr(tag, "type"))) {
                final String name = attr(tag, "name");
                if (name != null) {
                    out.putIfAbsent(name, unescape(attr(tag, "value")));
                }
            }
        }
        return out;
    }

    /** The {@code action} of the first {@code <form>} whose opening tag or body contains {@code marker}. */
    public static Optional<String> formAction(final String html, final String marker) {
        final Matcher m = FORM.matcher(html);
        while (m.find()) {
            if (m.group(0).contains(marker)) {
                return Optional.ofNullable(unescape(attr("<form " + m.group(1) + ">", "action")));
            }
        }
        return Optional.empty();
    }

    /** The full {@code <form>…</form>} markup of the first form containing {@code marker}. */
    public static Optional<String> form(final String html, final String marker) {
        final Matcher m = FORM.matcher(html);
        while (m.find()) {
            if (m.group(0).contains(marker)) {
                return Optional.of(m.group(0));
            }
        }
        return Optional.empty();
    }

    /** Values of every <i>checked</i> checkbox named {@code name} in the HTML fragment. */
    public static List<String> checkedValues(final String html, final String name) {
        final List<String> out = new ArrayList<>();
        final Matcher m = INPUT.matcher(html);
        while (m.find()) {
            final String tag = m.group();
            if ("checkbox".equalsIgnoreCase(attr(tag, "type")) && name.equals(attr(tag, "name"))
                    && tag.matches("(?is).*\\bchecked\\b.*")) {
                out.add(unescape(attr(tag, "value")));
            }
        }
        return out;
    }

    private static String attr(final String tag, final String name) {
        final Matcher m = Pattern.compile("\\b" + name + "\\s*=\\s*(\"([^\"]*)\"|'([^']*)')",
                Pattern.CASE_INSENSITIVE).matcher(tag);
        if (!m.find()) {
            return null;
        }
        return m.group(2) != null ? m.group(2) : m.group(3);
    }

    private static String unescape(final String v) {
        return v == null ? null : v.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&#x3D;", "=").replace("&#61;", "=");
    }

    static String snippet(final String body) {
        if (body == null) {
            return "<no body>";
        }
        return body.length() > 1500 ? body.substring(0, 1500) + "…" : body;
    }

    // ------------------------------------------------------------------------------------------------

    private HttpRequest.Builder request(final String pathOrUrl, final String... headers) {
        if (headers.length % 2 != 0) {
            throw new IllegalArgumentException("headers must be name/value pairs");
        }
        final HttpRequest.Builder b = HttpRequest.newBuilder(resolve(pathOrUrl)).timeout(Duration.ofSeconds(30));
        for (int i = 0; i < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        return b;
    }

    private Response send(final HttpRequest.Builder builder) {
        final HttpRequest request = builder.build();
        try {
            final HttpResponse<String> r = client.send(request, HttpResponse.BodyHandlers.ofString());
            history.add(request.method() + " " + request.uri() + " -> " + r.statusCode()
                    + r.headers().firstValue("Location").map(l -> " Location: " + l).orElse(""));
            return new Response(request.method(), r.statusCode(), r.uri(), r.headers(), r.body());
        } catch (final IOException e) {
            throw new UncheckedIOException(request.method() + " " + request.uri() + " failed", e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static String enc(final String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** An HTTP exchange's result. {@link #location()} is resolved against the request URI. */
    public record Response(String method, int status, URI uri, HttpHeaders headers, String body) {

        public boolean isRedirect() {
            return status >= 300 && status < 400 && headers.firstValue("Location").isPresent();
        }

        /** The absolute {@code Location} (relative values resolved against the request URI), or null. */
        public URI location() {
            return headers.firstValue("Location").map(uri::resolve).orElse(null);
        }

        public boolean locationStartsWith(final String prefix) {
            final URI loc = location();
            return loc != null && loc.toString().startsWith(prefix);
        }

        public Optional<String> header(final String name) {
            return headers.firstValue(name);
        }

        /** Parses the body as JSON. */
        public JsonNode json() {
            try {
                return JSON.readTree(body);
            } catch (final IOException e) {
                throw new AssertionError("Body is not JSON (" + this + ")", e);
            }
        }

        @Override
        public String toString() {
            return method + " " + uri + " -> " + status
                    + header("Location").map(l -> " Location: " + l).orElse("")
                    + "\n" + snippet(body);
        }
    }
}
