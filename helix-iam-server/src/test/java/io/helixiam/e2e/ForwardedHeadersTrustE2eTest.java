/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import io.helixiam.authorization.security.net.TrustedProxyForwardedHeaderFilter;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code X-Forwarded-Host/-Proto/-Port/-Prefix} and {@code Forwarded} are honoured only from a trusted proxy
 * ({@code helix.security.trusted-proxies}, empty in this context). From any other client they must not change the
 * issuer (SAS derives it from the request here), {@code isSecure()} or absolute URLs such as redirects.
 */
class ForwardedHeadersTrustE2eTest extends AbstractE2eTest {

    private static final String[] SPOOF = {"X-Forwarded-Host", "evil.example", "X-Forwarded-Proto", "https",
            "X-Forwarded-Port", "443", "X-Forwarded-Prefix", "/evil", "Forwarded", "host=evil.example;proto=https"};

    @Test
    void anUntrustedClientsForwardedHeaders_doNotChangeTheIssuer() {
        final E2eHttp.Response discovery = newBrowser().get("/realms/" + MASTER + "/.well-known/openid-configuration",
                SPOOF);

        assertThat(discovery.status()).as(discovery.toString()).isEqualTo(200);
        assertThat(discovery.json().path("issuer").asText()).isEqualTo(baseUrl() + "/realms/" + MASTER);
        assertThat(discovery.body()).doesNotContain("evil.example").doesNotContain("https://localhost");
    }

    @Test
    void anUntrustedClientsForwardedHeaders_doNotChangeRedirects() {
        // A page that needs a sign-in: the redirect to the login page is built from the request.
        final E2eHttp.Response redirect = newBrowser().get("/realms/" + MASTER + "/account", SPOOF);

        assertThat(redirect.status()).as(redirect.toString()).isBetween(300, 399);
        assertThat(redirect.header("Location").orElse("")).doesNotContain("evil.example").doesNotStartWith("https:");
    }

    @Test
    void theForwardedHeaderFilterInUse_isTheTrustCheckingOne() {
        assertThat(context.getBeansOfType(FilterRegistrationBean.class).values().stream()
                .map(FilterRegistrationBean::getFilter)
                .filter(f -> f instanceof org.springframework.web.filter.ForwardedHeaderFilter).toList())
                .singleElement().isInstanceOf(TrustedProxyForwardedHeaderFilter.class);
    }
}
