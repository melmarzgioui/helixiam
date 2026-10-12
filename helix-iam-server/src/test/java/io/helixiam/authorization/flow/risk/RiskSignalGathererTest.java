/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.risk;

import io.helixiam.authorization.security.net.ClientIpResolver;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** Risk signals use the shared client-IP resolver, so a made-up X-Forwarded-For cannot fake a known IP. */
class RiskSignalGathererTest {

    private static MockHttpServletRequest request(final String peer, final String xff, final String realIp) {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr(peer);
        request.addHeader("X-Forwarded-For", xff);
        request.addHeader("X-Real-IP", realIp);
        return request;
    }

    @Test
    void aSpoofedForwardedIp_fromAnUntrustedPeer_isIgnored() {
        final RiskSignalGatherer gatherer = new RiskSignalGatherer(new ClientIpResolver(""));

        assertThat(gatherer.gather(request("198.51.100.20", "203.0.113.66", "203.0.113.77")).ip())
                .isEqualTo("198.51.100.20");
    }

    @Test
    void aTrustedProxy_isHonoured() {
        final RiskSignalGatherer gatherer = new RiskSignalGatherer(new ClientIpResolver("10.0.0.0/8"));

        assertThat(gatherer.gather(request("10.0.0.1", "203.0.113.66", "203.0.113.77")).ip()).isEqualTo("203.0.113.66");
    }
}
