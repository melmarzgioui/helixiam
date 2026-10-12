/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.net;

import jakarta.servlet.DispatcherType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.ForwardedHeaderFilter;

/**
 * Registers {@link TrustedProxyForwardedHeaderFilter} in place of the {@code ForwardedHeaderFilter} Spring Boot
 * registers for {@code server.forward-headers-strategy=framework} (Boot backs off when a bean of that filter type
 * exists). Same order and dispatcher types as Boot's own registration.
 */
@Configuration
public class ForwardedHeadersConfig {

    private static final Logger LOG = LogManager.getLogger(ForwardedHeadersConfig.class);

    @Bean
    @ConditionalOnProperty(value = "server.forward-headers-strategy", havingValue = "framework")
    public FilterRegistrationBean<ForwardedHeaderFilter> trustedProxyForwardedHeaderFilter(
            final ClientIpResolver clientIps, @Value("${idp.base.url:}") final String idpBaseUrl) {
        if (!clientIps.hasTrustedProxies() && idpBaseUrl != null && idpBaseUrl.startsWith("https://")) {
            LOG.warn("IDP_BASE_URL is https but HELIX_TRUSTED_PROXIES is empty: X-Forwarded-Proto/-Host from a TLS-"
                    + "terminating proxy are ignored, so the request-derived issuer and redirects use the scheme and "
                    + "host the server sees. List the proxy in HELIX_TRUSTED_PROXIES unless TLS ends at this server.");
        }
        // Typed as FilterRegistrationBean<ForwardedHeaderFilter> so Boot's @ConditionalOnMissingFilterBean sees it.
        final FilterRegistrationBean<ForwardedHeaderFilter> registration =
                new FilterRegistrationBean<>(new TrustedProxyForwardedHeaderFilter(clientIps));
        registration.setDispatcherTypes(DispatcherType.REQUEST, DispatcherType.ASYNC, DispatcherType.ERROR);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
