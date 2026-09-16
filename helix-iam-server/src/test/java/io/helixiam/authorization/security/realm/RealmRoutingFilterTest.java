/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.realm;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM multi-tenant (MT-1): the realm routing filter treats {@code /realms/{realm}} as a virtual
 * servlet context-path extension, bypasses {@code /admin}, and 404s flat (non-realm) protocol paths.
 */
class RealmRoutingFilterTest {

    private final RealmRoutingFilter filter = new RealmRoutingFilter();

    @Test
    void realmPath_virtualizesContextPath_stripsServletPath_andBindsRealm() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/realms/gov/oauth2/token");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final AtomicReference<String> seenContextPath = new AtomicReference<>();
        final AtomicReference<String> seenServletPath = new AtomicReference<>();
        final AtomicReference<String> seenRealm = new AtomicReference<>();
        final MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                final HttpServletRequest http = (HttpServletRequest) req;
                seenContextPath.set(http.getContextPath());
                seenServletPath.set(http.getServletPath());
                seenRealm.set(RealmContextHolder.get());
            }
        };

        filter.doFilter(request, response, chain);

        assertThat(seenContextPath.get()).isEqualTo("/realms/gov");
        assertThat(seenServletPath.get()).isEqualTo("/oauth2/token");
        assertThat(seenRealm.get()).isEqualTo("gov");
        // The realm is unbound again once the request leaves the filter (no thread-local leak).
        assertThat(RealmContextHolder.get()).isNull();
    }

    @Test
    void adminPath_passesThroughUntouched_withoutBindingRealm() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/realms/gov/endpoints");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final AtomicReference<String> seenContextPath = new AtomicReference<>();
        final AtomicReference<String> seenRealm = new AtomicReference<>();
        final MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                seenContextPath.set(((HttpServletRequest) req).getContextPath());
                seenRealm.set(RealmContextHolder.get());
            }
        };

        filter.doFilter(request, response, chain);

        assertThat(seenContextPath.get()).isEmpty();   // not virtualized
        assertThat(seenRealm.get()).isNull();          // no realm bound for admin
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void staticAssetPath_passesThroughUntouched_withoutBindingRealm() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/css/font/WorkSans.woff2");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final boolean[] forwarded = {false};
        final AtomicReference<String> seenContextPath = new AtomicReference<>();
        final MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                forwarded[0] = true;
                seenContextPath.set(((HttpServletRequest) req).getContextPath());
            }
        };

        filter.doFilter(request, response, chain);

        // Static login-page assets are realm-agnostic: served at their flat path, not virtualized or 404'd.
        assertThat(forwarded[0]).isTrue();
        assertThat(seenContextPath.get()).isEmpty();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void unknownRealm_is404_andNotForwarded_whenResolverPresent() throws Exception {
        final RealmSettingsResolver realms = org.mockito.Mockito.mock(RealmSettingsResolver.class);
        org.mockito.Mockito.when(realms.exists("ghost")).thenReturn(false);
        final RealmRoutingFilter guarded = new RealmRoutingFilter(realms);

        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/ghost/.well-known/openid-configuration");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final boolean[] forwarded = {false};
        final MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                forwarded[0] = true;
            }
        };

        guarded.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(forwarded[0]).isFalse();
        assertThat(RealmContextHolder.get()).isNull();
    }

    @Test
    void knownRealm_isForwarded_whenResolverPresent() throws Exception {
        final RealmSettingsResolver realms = org.mockito.Mockito.mock(RealmSettingsResolver.class);
        org.mockito.Mockito.when(realms.exists("master")).thenReturn(true);
        final RealmRoutingFilter guarded = new RealmRoutingFilter(realms);

        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/master/.well-known/openid-configuration");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final boolean[] forwarded = {false};
        final MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                forwarded[0] = true;
            }
        };

        guarded.doFilter(request, response, chain);

        assertThat(forwarded[0]).isTrue();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void flatProtocolPath_is404_andNotForwarded() throws Exception {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/.well-known/openid-configuration");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final boolean[] forwarded = {false};
        final MockFilterChain chain = new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                forwarded[0] = true;
            }
        };

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(forwarded[0]).isFalse();
    }
}
