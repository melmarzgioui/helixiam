/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** 1.0 item 4: which requests the admin bearer filter handles, and how a token's realm is derived. */
class AdminBearerTokenFilterTest {

    @Test
    void realmIsTheLastSegmentOfARealmIssuer() {
        assertThat(AdminBearerTokenFilter.realmOf("https://idp.example.com/realms/monthfold")).isEqualTo("monthfold");
        assertThat(AdminBearerTokenFilter.realmOf("http://localhost:8080/realms/master")).isEqualTo("master");
        assertThat(AdminBearerTokenFilter.realmOf("https://idp.example.com")).isNull();
        assertThat(AdminBearerTokenFilter.realmOf("https://idp.example.com/realms/")).isNull();
        assertThat(AdminBearerTokenFilter.realmOf("https://idp.example.com/realms/a/b")).isNull();
        assertThat(AdminBearerTokenFilter.realmOf(null)).isNull();
    }

    @Test
    void onlyAdminRequestsWithABearerHeaderAreHandled() {
        assertThat(AdminBearerTokenFilter.isAdminBearerRequest(request("/admin/realms/x/clients", "Bearer abc"))).isTrue();
        assertThat(AdminBearerTokenFilter.isAdminBearerRequest(request("/admin/realms/x/clients", "bearer abc"))).isTrue();
        assertThat(AdminBearerTokenFilter.isAdminBearerRequest(request("/admin/realms/x/clients", null))).isFalse();
        assertThat(AdminBearerTokenFilter.isAdminBearerRequest(request("/admin/realms/x/clients", "Basic abc"))).isFalse();
        assertThat(AdminBearerTokenFilter.isAdminBearerRequest(request("/account/profile", "Bearer abc"))).isFalse();
    }

    private static MockHttpServletRequest request(final String uri, final String authorization) {
        final MockHttpServletRequest r = new MockHttpServletRequest("GET", uri);
        if (authorization != null) {
            r.addHeader("Authorization", authorization);
        }
        return r;
    }
}
