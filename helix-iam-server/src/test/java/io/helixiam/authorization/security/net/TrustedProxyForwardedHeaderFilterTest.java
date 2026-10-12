/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring's forwarded-header handling ({@code server.forward-headers-strategy=framework}) applied only to requests
 * whose TCP peer is a trusted proxy; from anyone else the forwarded headers are removed and ignored.
 */
class TrustedProxyForwardedHeaderFilterTest {

    private static MockHttpServletRequest spoofed(final String peer) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/master/login");
        request.setRemoteAddr(peer);
        request.setServerName("localhost");
        request.setServerPort(8080);
        request.addHeader("X-Forwarded-Host", "evil.example");
        request.addHeader("X-Forwarded-Proto", "https");
        request.addHeader("X-Forwarded-Port", "443");
        request.addHeader("X-Forwarded-Prefix", "/evil");
        request.addHeader("Forwarded", "host=evil.example;proto=https");
        return request;
    }

    private record Seen(HttpServletRequest request, String location) {
    }

    private static Seen run(final String trustedProxies, final MockHttpServletRequest request) throws Exception {
        final TrustedProxyForwardedHeaderFilter filter =
                new TrustedProxyForwardedHeaderFilter(new ClientIpResolver(trustedProxies));
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final MockFilterChain chain = new MockFilterChain(new jakarta.servlet.http.HttpServlet() {
            @Override
            protected void service(final HttpServletRequest req, final HttpServletResponse res) throws java.io.IOException {
                res.sendRedirect("/next");
            }
        });
        filter.doFilter(request, response, chain);
        return new Seen((HttpServletRequest) chain.getRequest(), response.getRedirectedUrl());
    }

    @Test
    void anUntrustedPeer_changesNeitherSchemeHostSecureNorAbsoluteUrls() throws Exception {
        final Seen seen = run("10.0.0.0/8", spoofed("198.51.100.20"));

        assertThat(seen.request().isSecure()).isFalse();
        assertThat(seen.request().getScheme()).isEqualTo("http");
        assertThat(seen.request().getServerName()).isEqualTo("localhost");
        assertThat(seen.request().getServerPort()).isEqualTo(8080);
        assertThat(seen.request().getRequestURL().toString()).isEqualTo("http://localhost:8080/realms/master/login");
        assertThat(seen.request().getHeader("X-Forwarded-Host")).isNull();
        assertThat(seen.request().getHeader("Forwarded")).isNull();
        assertThat(seen.location()).doesNotContain("evil");
    }

    @Test
    void aTrustedProxy_isHonoured() throws Exception {
        final MockHttpServletRequest request = spoofed("10.1.2.3");
        request.removeHeader("Forwarded"); // Forwarded takes precedence; keep the X-Forwarded-* set here

        final Seen seen = run("10.0.0.0/8", request);

        assertThat(seen.request().isSecure()).isTrue();
        assertThat(seen.request().getScheme()).isEqualTo("https");
        assertThat(seen.request().getServerName()).isEqualTo("evil.example");
        assertThat(seen.request().getRequestURL().toString()).isEqualTo("https://evil.example/evil/realms/master/login");
        assertThat(seen.location()).isEqualTo("https://evil.example/next"); // an absolute-path redirect gets no prefix
    }

    @Test
    void theStandardForwardedHeader_isHonouredFromATrustedProxy() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/x");
        request.setRemoteAddr("10.1.2.3");
        request.addHeader("Forwarded", "for=203.0.113.5;host=idp.example.com;proto=https");

        assertThat(run("10.0.0.0/8", request).request().getRequestURL().toString()).isEqualTo("https://idp.example.com/x");
    }

    @Test
    void withNoTrustedProxies_nothingIsHonoured() throws Exception {
        final Seen seen = run("", spoofed("127.0.0.1"));

        assertThat(seen.request().isSecure()).isFalse();
        assertThat(seen.request().getServerName()).isEqualTo("localhost");
    }
}
