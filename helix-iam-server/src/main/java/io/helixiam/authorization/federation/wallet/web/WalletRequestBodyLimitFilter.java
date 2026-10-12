/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Task 18: the body limit of the OpenID4VP endpoints ({@code /realms/<realm>/oid4vp/**}, reached by wallets without a
 * session): 256 KB by default ({@code helix.wallet.max-request-bytes}). It runs right after the realm routing, before
 * Spring Security and before anything reads the body:
 *
 * <ul>
 *   <li>a declared {@code Content-Length} over the limit is refused with {@code 413} without reading a byte;</li>
 *   <li>otherwise a POST body is read here, at most the limit plus one byte (a chunked body without a length cannot
 *       make the server buffer more), and refused with {@code 413} when it is longer;</li>
 *   <li>a body within the limit is parsed here once ({@code application/x-www-form-urlencoded}, UTF-8) and handed on as
 *       the request's parameters and input stream, so the container never parses it again.</li>
 * </ul>
 * Refusals answer {@code {"error":"invalid_request"}} (OpenID4VP §8.5 codes only, no detail).
 */
public class WalletRequestBodyLimitFilter extends OncePerRequestFilter {

    /** The default body limit (constraints: response body 256 KB). */
    public static final int DEFAULT_MAX_BYTES = 256 * 1024;
    private static final String PATH_PREFIX = "/oid4vp/";
    private static final String ERROR_BODY = "{\"error\":\"invalid_request\"}";
    private static final int CHUNK = 8192;

    private final int maxBytes;

    public WalletRequestBodyLimitFilter(final int maxBytes) {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("The wallet request body limit must be positive");
        }
        this.maxBytes = maxBytes;
    }

    @Override
    protected boolean shouldNotFilter(final HttpServletRequest request) {
        final String path = request.getServletPath();
        return path == null || !path.startsWith(PATH_PREFIX);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
                                    final FilterChain chain) throws ServletException, IOException {
        if (request.getContentLengthLong() > maxBytes) {
            refuse(response, 413);
            return;
        }
        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            chain.doFilter(request, response);
            return;
        }
        final byte[] body = readAtMost(request.getInputStream(), maxBytes + 1);
        if (body.length > maxBytes) {
            refuse(response, 413);
            return;
        }
        final Map<String, String[]> parameters;
        try {
            parameters = parameters(request, body);
        } catch (final IllegalArgumentException e) {
            refuse(response, HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        chain.doFilter(new BufferedRequest(request, body, parameters), response);
    }

    private static byte[] readAtMost(final InputStream in, final int limit) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buffer = new byte[CHUNK];
        while (out.size() < limit) {
            final int n = in.read(buffer, 0, Math.min(buffer.length, limit - out.size()));
            if (n < 0) {
                break;
            }
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    private static void refuse(final HttpServletResponse response, final int status) throws IOException {
        response.setStatus(status);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(ERROR_BODY);
    }

    /** The query-string parameters, then the form body's (when it is a form), in order. */
    private static Map<String, String[]> parameters(final HttpServletRequest request, final byte[] body) {
        final Map<String, List<String>> values = new LinkedHashMap<>();
        addPairs(values, request.getQueryString());
        final String type = request.getContentType();
        if (type != null && type.toLowerCase(java.util.Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            addPairs(values, new String(body, StandardCharsets.UTF_8));
        }
        final Map<String, String[]> out = new LinkedHashMap<>();
        values.forEach((k, v) -> out.put(k, v.toArray(new String[0])));
        return Collections.unmodifiableMap(out);
    }

    private static void addPairs(final Map<String, List<String>> values, final String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return;
        }
        for (final String pair : encoded.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            final int eq = pair.indexOf('=');
            final String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), StandardCharsets.UTF_8);
            final String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            values.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
    }

    /** The request with its body already read: parameters and stream come from the buffered copy. */
    private static final class BufferedRequest extends HttpServletRequestWrapper {

        private final byte[] body;
        private final Map<String, String[]> parameters;

        BufferedRequest(final HttpServletRequest request, final byte[] body, final Map<String, String[]> parameters) {
            super(request);
            this.body = body;
            this.parameters = parameters;
        }

        @Override
        public String getParameter(final String name) {
            final String[] v = parameters.get(name);
            return v == null || v.length == 0 ? null : v[0];
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            return parameters;
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(parameters.keySet());
        }

        @Override
        public String[] getParameterValues(final String name) {
            final String[] v = parameters.get(name);
            return v == null ? null : v.clone();
        }

        @Override
        public int getContentLength() {
            return body.length;
        }

        @Override
        public long getContentLengthLong() {
            return body.length;
        }

        @Override
        public ServletInputStream getInputStream() {
            final ByteArrayInputStream in = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public int read() {
                    return in.read();
                }

                @Override
                public int read(final byte[] b, final int off, final int len) {
                    return in.read(b, off, len);
                }

                @Override
                public boolean isFinished() {
                    return in.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(final ReadListener listener) {
                    throw new UnsupportedOperationException("Blocking reads only");
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }
}
