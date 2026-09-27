/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.theme.render;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** Item 6: which message the themed error page shows, and which requests get it. */
class ProtocolErrorPageFilterTest {

    private static MockHttpServletRequest request(final String servletPath, final String clientId) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/monthfold" + servletPath);
        request.setContextPath("/realms/monthfold");
        request.setServletPath(servletPath);
        if (clientId != null) {
            request.setParameter("client_id", clientId);
        }
        return request;
    }

    @Test
    void theKind_comesFromTheStatus_theEndpoint_andTheServersMessage() {
        assertThat(ProtocolErrorPageFilter.classify(request("/oauth2/authorize", "nope"), 400,
                "[invalid_request] OAuth 2.0 Parameter: client_id")).isEqualTo(ProtocolErrorPageFilter.Kind.CLIENT);
        assertThat(ProtocolErrorPageFilter.classify(request("/oauth2/authorize", null), 400,
                "[invalid_request] OAuth 2.0 Parameter: client_id")).isEqualTo(ProtocolErrorPageFilter.Kind.REQUEST);
        assertThat(ProtocolErrorPageFilter.classify(request("/oauth2/authorize", "web"), 400,
                "[invalid_request] OAuth 2.0 Parameter: redirect_uri")).isEqualTo(ProtocolErrorPageFilter.Kind.REDIRECT);
        assertThat(ProtocolErrorPageFilter.classify(request("/connect/logout", null), 400,
                "[invalid_request] OAuth 2.0 Parameter: id_token_hint")).isEqualTo(ProtocolErrorPageFilter.Kind.LOGOUT);
        assertThat(ProtocolErrorPageFilter.classify(request("/nothing", null), 404, null))
                .isEqualTo(ProtocolErrorPageFilter.Kind.NOT_FOUND);
        assertThat(ProtocolErrorPageFilter.classify(request("/login", null), 403, null))
                .isEqualTo(ProtocolErrorPageFilter.Kind.FORBIDDEN);
        assertThat(ProtocolErrorPageFilter.classify(request("/login", null), 405, null))
                .isEqualTo(ProtocolErrorPageFilter.Kind.GENERIC);
    }

    @Test
    void onlyAStandardErrorCode_isShown() {
        assertThat(ProtocolErrorPageFilter.code("[invalid_request] OAuth 2.0 Parameter: client_id"))
                .isEqualTo("invalid_request");
        assertThat(ProtocolErrorPageFilter.code("[<script>] x")).isNull();
        assertThat(ProtocolErrorPageFilter.code("invalid_request")).isNull();
        assertThat(ProtocolErrorPageFilter.code("[]")).isNull();
        assertThat(ProtocolErrorPageFilter.code(null)).isNull();
    }

    @Test
    void onlyARequestForHtml_getsThePage() {
        final MockHttpServletRequest browser = request("/oauth2/authorize", null);
        browser.addHeader("Accept", "text/html,application/xhtml+xml,*/*;q=0.8");
        assertThat(ProtocolErrorPageFilter.wantsHtml(browser)).isTrue();
        final MockHttpServletRequest api = request("/oauth2/authorize", null);
        api.addHeader("Accept", "application/json");
        assertThat(ProtocolErrorPageFilter.wantsHtml(api)).isFalse();
        assertThat(ProtocolErrorPageFilter.wantsHtml(request("/oauth2/authorize", null))).isFalse();
    }
}
