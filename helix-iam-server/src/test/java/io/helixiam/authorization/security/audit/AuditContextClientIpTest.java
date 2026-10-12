/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.audit;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** The audit trail records the client IP from the shared resolver: a spoofed X-Forwarded-For is not recorded. */
class AuditContextClientIpTest {

    @Test
    void aSpoofedXForwardedFor_fromAnUntrustedPeer_isNotTheAuditIp() {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setRemoteAddr("198.51.100.20");
        request.addHeader("X-Forwarded-For", "203.0.113.66");

        assertThat(AuditContext.clientIp(request)).isEqualTo("198.51.100.20");
    }
}
