/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 18: the wallet endpoints refuse a body over the limit with 413 before it is buffered or parsed: a declared
 * {@code Content-Length} over the limit is refused unread, and a body without one is read only up to the limit plus
 * one byte. A body within the limit is parsed once, here, and handed on as the request's parameters.
 */
class WalletRequestBodyLimitFilterTest {

    private static final int LIMIT = 1024;

    private final WalletRequestBodyLimitFilter filter = new WalletRequestBodyLimitFilter(LIMIT);

    private static MockHttpServletRequest post(final String path) {
        // The filter runs before the realm routing (and Spring's FormContentFilter): it matches the raw URI.
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/realms/acme" + path);
        request.setContentType("application/x-www-form-urlencoded");
        return request;
    }

    @Test
    void aDeclaredLengthOverTheLimit_is413_withoutReadingTheBody() throws Exception {
        final AtomicLong read = new AtomicLong();
        final MockHttpServletRequest request = post("/oid4vp/eudi/response/r1");
        request.addHeader("Content-Length", String.valueOf(300 * 1024));
        final HttpServletRequest counting = new jakarta.servlet.http.HttpServletRequestWrapper(request) {
            @Override
            public long getContentLengthLong() {
                return 300 * 1024;
            }

            @Override
            public ServletInputStream getInputStream() {
                return endless(read);
            }
        };
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(counting, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"invalid_request\"}");
        assertThat(chain.getRequest()).isNull();
        assertThat(read.get()).isZero();
    }

    @Test
    void anUndeclaredLength_isReadOnlyUpToTheLimit() throws Exception {
        final AtomicLong read = new AtomicLong();
        final HttpServletRequest chunked = new jakarta.servlet.http.HttpServletRequestWrapper(
                post("/oid4vp/eudi/response/r1")) {
            @Override
            public long getContentLengthLong() {
                return -1;
            }

            @Override
            public int getContentLength() {
                return -1;
            }

            @Override
            public ServletInputStream getInputStream() {
                return endless(read);
            }
        };
        final MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(chunked, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(read.get()).isLessThanOrEqualTo(LIMIT + 1 + 8192);
    }

    @Test
    void aBodyWithinTheLimit_isParsedOnce_andPassedOnAsParameters() throws Exception {
        final MockHttpServletRequest request = post("/oid4vp/eudi/response/r1");
        request.setContent("response=a%2Bb&state=s&state=t".getBytes(StandardCharsets.UTF_8));
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        final HttpServletRequest passed = (HttpServletRequest) chain.getRequest();
        assertThat(passed.getParameter("response")).isEqualTo("a+b");
        assertThat(passed.getParameterValues("state")).containsExactly("s", "t");
        assertThat(passed.getParameterMap()).containsOnlyKeys("response", "state");
    }

    @Test
    void otherPaths_areNotTouched() throws Exception {
        final MockHttpServletRequest request = post("/login");
        request.addHeader("Content-Length", String.valueOf(300 * 1024));
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    /** Body only (OpenID4VP §8.2): a vp_token or state in the URL would end up in access logs, so it is not read. */
    @Test
    void queryStringParameters_areNotParameters() throws Exception {
        final MockHttpServletRequest request = post("/oid4vp/eudi/response/r1");
        request.setQueryString("vp_token=from-url&state=from-url");
        request.addParameter("vp_token", "from-url"); // what the container would have parsed
        request.setContent("response=jwe".getBytes(StandardCharsets.UTF_8));
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        final HttpServletRequest passed = (HttpServletRequest) chain.getRequest();
        assertThat(passed.getParameterMap()).containsOnlyKeys("response");
        assertThat(passed.getParameter("vp_token")).isNull();
        assertThat(passed.getParameter("state")).isNull();
    }

    /** Only GET and POST exist here: any other method is refused before a byte of its body is read. */
    @Test
    void otherMethods_are405_withoutReadingTheBody() throws Exception {
        for (final String method : java.util.List.of("PUT", "PATCH", "DELETE", "OPTIONS")) {
            final AtomicLong read = new AtomicLong();
            final MockHttpServletRequest raw = new MockHttpServletRequest(method, "/realms/acme/oid4vp/eudi/response/r1");
            raw.setContentType("application/x-www-form-urlencoded");
            final HttpServletRequest chunked = new jakarta.servlet.http.HttpServletRequestWrapper(raw) {
                @Override
                public long getContentLengthLong() {
                    return -1;
                }

                @Override
                public ServletInputStream getInputStream() {
                    return endless(read);
                }
            };
            final MockHttpServletResponse response = new MockHttpServletResponse();
            final MockFilterChain chain = new MockFilterChain();

            filter.doFilter(chunked, response, chain);

            assertThat(response.getStatus()).as(method).isEqualTo(405);
            assertThat(response.getHeader("Allow")).isEqualTo("GET, POST");
            assertThat(chain.getRequest()).isNull();
            assertThat(read.get()).isZero();
        }
    }

    @Test
    void aGet_passesWithoutBuffering() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/acme/oid4vp/eudi/request/q1");
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
    }

    // ------------------------------------------------------------------ the login page's DC API posts

    @Test
    void aDcApiPostOverTheLimit_is413_beforeAnyOtherFilterReadsIt() throws Exception {
        final MockHttpServletRequest request = post("/broker/eudi/wallet/dc-api/response");
        request.setQueryString("tx=t1");
        request.setContent(("_csrf=x&data=" + "a".repeat(2 * 1024 * 1024)).getBytes(StandardCharsets.US_ASCII));
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(chain.getRequest()).isNull();
    }

    @Test
    void aDcApiPostWithinTheLimit_keepsItsQueryParameters_andItsJsonBody() throws Exception {
        for (final String kind : new String[] {"request", "response"}) {
            final MockHttpServletRequest request = post("/broker/eudi/wallet/dc-api/" + kind);
            request.setContentType("application/json");
            request.setQueryString("tx=t%2B1");
            request.addParameter("tx", "t+1");
            request.setContent("{\"protocol\":\"p\"}".getBytes(StandardCharsets.UTF_8));
            final MockFilterChain chain = new MockFilterChain();

            filter.doFilter(request, new MockHttpServletResponse(), chain);

            final HttpServletRequest passed = (HttpServletRequest) chain.getRequest();
            assertThat(passed.getParameter("tx")).isEqualTo("t+1");
            assertThat(passed.getParameterMap()).containsOnlyKeys("tx");
            assertThat(new String(passed.getInputStream().readAllBytes(), StandardCharsets.UTF_8))
                    .isEqualTo("{\"protocol\":\"p\"}");
        }
    }

    @Test
    void otherWalletPagePaths_areNotTouched() throws Exception {
        for (final String path : new String[] {"/broker/eudi/wallet", "/broker/eudi/wallet/status",
                "/broker/eudi/callback", "/broker/eudi/wallet/dc-api"}) {
            final MockHttpServletRequest request = post(path);
            final MockFilterChain chain = new MockFilterChain();
            filter.doFilter(request, new MockHttpServletResponse(), chain);
            assertThat(chain.getRequest()).as(path).isSameAs(request);
        }
    }

    private static ServletInputStream endless(final AtomicLong read) {
        return new ServletInputStream() {
            @Override
            public int read() {
                read.incrementAndGet();
                return 'a';
            }

            @Override
            public int read(final byte[] b, final int off, final int len) throws IOException {
                for (int i = 0; i < len; i++) {
                    b[off + i] = 'a';
                }
                read.addAndGet(len);
                return len;
            }

            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(final ReadListener readListener) {
                throw new UnsupportedOperationException();
            }
        };
    }
}
