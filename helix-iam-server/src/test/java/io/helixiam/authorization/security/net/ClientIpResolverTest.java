/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.filter.ForwardedHeaderFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The client IP used for rate limits, audit events, risk signals and CAPTCHA checks. {@code X-Forwarded-For} is
 * client-controlled, so it is honoured only when the direct peer is a configured trusted proxy, and then walked from
 * the right: the first address that is not a trusted proxy is the client. Anything to its left was written by the
 * client and is ignored.
 */
class ClientIpResolverTest {

    private static MockHttpServletRequest from(final String peer, final String... xff) {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr(peer);
        for (final String value : xff) {
            request.addHeader("X-Forwarded-For", value);
        }
        return request;
    }

    @Test
    void byDefault_theSocketPeerIsTheClient_andForwardedHeadersAreIgnored() {
        final ClientIpResolver resolver = new ClientIpResolver("");
        final MockHttpServletRequest request = from("198.51.100.20", "203.0.113.66");
        request.addHeader("X-Real-IP", "203.0.113.77");

        assertThat(resolver.resolve(request)).isEqualTo("198.51.100.20");
    }

    @Test
    void aSpoofedHeaderFromAnUntrustedPeer_isIgnored() {
        final ClientIpResolver resolver = new ClientIpResolver("10.0.0.0/8");

        assertThat(resolver.resolve(from("198.51.100.20", "203.0.113.66"))).isEqualTo("198.51.100.20");
    }

    @Test
    void aTrustedProxy_isHonoured() {
        final ClientIpResolver resolver = new ClientIpResolver("10.0.0.0/8");

        assertThat(resolver.resolve(from("10.1.2.3", "203.0.113.5"))).isEqualTo("203.0.113.5");
    }

    @Test
    void theWalkReturnsTheRightMostAddressThatIsNotATrustedProxy() {
        // client spoofs "1.1.1.1"; the edge proxy appends the real client; an inner proxy appends the edge proxy.
        final ClientIpResolver resolver = new ClientIpResolver("10.0.0.0/8, 192.168.1.10");

        assertThat(resolver.resolve(from("10.0.0.2", "1.1.1.1, 203.0.113.5, 192.168.1.10"))).isEqualTo("203.0.113.5");
        // Several header lines are one list, in order.
        assertThat(resolver.resolve(from("10.0.0.2", "1.1.1.1", "203.0.113.5", "192.168.1.10")))
                .isEqualTo("203.0.113.5");
    }

    @Test
    void whenEveryHopIsATrustedProxy_theLeftMostIsTheClient() {
        final ClientIpResolver resolver = new ClientIpResolver("10.0.0.0/8");

        assertThat(resolver.resolve(from("10.0.0.2", "10.9.9.9, 10.0.0.1"))).isEqualTo("10.9.9.9");
    }

    @Test
    void xRealIp_isUsedOnlyFromATrustedProxy_withoutXForwardedFor() {
        final ClientIpResolver resolver = new ClientIpResolver("10.0.0.1");
        final MockHttpServletRequest trusted = from("10.0.0.1");
        trusted.addHeader("X-Real-IP", "203.0.113.9");
        final MockHttpServletRequest untrusted = from("198.51.100.20");
        untrusted.addHeader("X-Real-IP", "203.0.113.9");

        assertThat(resolver.resolve(trusted)).isEqualTo("203.0.113.9");
        assertThat(resolver.resolve(untrusted)).isEqualTo("198.51.100.20");
    }

    @Test
    void ipv6_peersHopsAndRanges() {
        final ClientIpResolver resolver = new ClientIpResolver("2001:db8::/32, ::1");

        assertThat(resolver.resolve(from("2001:db8:0:0:0:0:0:7", "2001:db8:ffff::1, 2a00:1450:4001::5")))
                .isEqualTo("2a00:1450:4001:0:0:0:0:5");
        assertThat(resolver.resolve(from("0:0:0:0:0:0:0:1", "[2a00:1450:4001::5]:443"))).isEqualTo("2a00:1450:4001:0:0:0:0:5");
        assertThat(resolver.resolve(from("2a00:1450:4001::9", "203.0.113.5"))).isEqualTo("2a00:1450:4001:0:0:0:0:9");
        // An IPv4 hop with a port.
        assertThat(resolver.resolve(from("::1", "203.0.113.5:51234"))).isEqualTo("203.0.113.5");
    }

    @Test
    void aMalformedHop_stopsTheWalk_atTheLastTrustedAddress() {
        final ClientIpResolver resolver = new ClientIpResolver("10.0.0.0/8");

        assertThat(resolver.resolve(from("10.0.0.2", "garbage"))).isEqualTo("10.0.0.2");
        assertThat(resolver.resolve(from("10.0.0.2", "203.0.113.5, not-an-ip, 10.0.0.1"))).isEqualTo("10.0.0.1");
        assertThat(resolver.resolve(from("10.0.0.2", ""))).isEqualTo("10.0.0.2");
        assertThat(resolver.resolve(from("10.0.0.2", " , ,"))).isEqualTo("10.0.0.2");
        // Valid hops to the right of a malformed one still count.
        assertThat(resolver.resolve(from("10.0.0.2", "junk, 203.0.113.5"))).isEqualTo("203.0.113.5");
        // A host name is never resolved (no DNS lookup on client input): it is malformed.
        assertThat(resolver.resolve(from("10.0.0.2", "localhost"))).isEqualTo("10.0.0.2");
    }

    @Test
    void readsTheSocketPeerUnderneathSpringsForwardedHeaderFilter() throws Exception {
        // server.forward-headers-strategy=framework wraps the request so getRemoteAddr() is the LEFT-most
        // X-Forwarded-For entry (client-controlled) and the header itself is hidden. The resolver reads the
        // container's own request instead.
        final MockHttpServletRequest raw = from("198.51.100.20", "203.0.113.66");
        final MockFilterChain chain = new MockFilterChain();
        new ForwardedHeaderFilter().doFilter(raw, new MockHttpServletResponse(), chain);
        final HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
        assertThat(wrapped.getRemoteAddr()).isEqualTo("203.0.113.66"); // what Spring would have trusted

        assertThat(new ClientIpResolver("").resolve(wrapped)).isEqualTo("198.51.100.20");
        assertThat(new ClientIpResolver("198.51.100.0/24").resolve(wrapped)).isEqualTo("203.0.113.66");
    }

    @Test
    void anInvalidTrustedProxyEntry_failsAtStartup() {
        assertThatThrownBy(() -> new ClientIpResolver("10.0.0.0/33"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("helix.security.trusted-proxies");
        assertThatThrownBy(() -> new ClientIpResolver("proxy.internal"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aNullRequestHasNoIp() {
        assertThat(new ClientIpResolver("").resolve(null)).isNull();
    }
}
