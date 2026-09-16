package io.helixiam.authorization.security.realm;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers {@link RealmRoutingFilter} just <b>ahead of</b> Spring Security's {@code FilterChainProxy}
 * (which sits at {@link SecurityProperties#DEFAULT_FILTER_ORDER}), so the realm prefix is resolved and the
 * request virtualized before any security matching runs.
 */
@Configuration
public class RealmRoutingConfig {

    @Bean
    public FilterRegistrationBean<RealmRoutingFilter> realmRoutingFilter(final RealmSettingsResolver realmSettingsResolver) {
        final FilterRegistrationBean<RealmRoutingFilter> registration =
                new FilterRegistrationBean<>(new RealmRoutingFilter(realmSettingsResolver));
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 10);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
