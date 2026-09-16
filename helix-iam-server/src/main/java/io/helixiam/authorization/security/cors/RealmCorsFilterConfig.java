package io.helixiam.authorization.security.cors;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CorsFilter;

/**
 * Helix IAM (CORS): registers a standalone {@link CorsFilter} backed by the realm/client web-origin
 * allowlist ({@link RealmClientCorsConfigurationSource}). It runs <b>after</b> the realm routing filter
 * (so the realm context is set) but <b>before</b> Spring Security's {@code FilterChainProxy}, so a
 * cross-origin preflight ({@code OPTIONS}) is answered with the right headers and short-circuited before
 * any authentication can redirect it to login — and actual requests get the headers uniformly across both
 * security chains.
 */
@Configuration
public class RealmCorsFilterConfig {

    @Bean
    public FilterRegistrationBean<CorsFilter> realmCorsFilter(final RealmClientCorsConfigurationSource source) {
        final FilterRegistrationBean<CorsFilter> registration = new FilterRegistrationBean<>(new CorsFilter(source));
        // Between the realm routing filter (DEFAULT_FILTER_ORDER - 10) and Spring Security (DEFAULT_FILTER_ORDER).
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 5);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
