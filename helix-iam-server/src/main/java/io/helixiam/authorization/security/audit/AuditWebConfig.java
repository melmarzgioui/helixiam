package io.helixiam.authorization.security.audit;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Helix IAM E8.5-S4 (Events): registers the admin audit interceptor on {@code /admin/**} and enables the
 * {@link HelixAuditProperties} binding.
 */
@Configuration
@EnableConfigurationProperties(HelixAuditProperties.class)
public class AuditWebConfig implements WebMvcConfigurer {

    private final AuditAdminInterceptor auditAdminInterceptor;

    public AuditWebConfig(final AuditAdminInterceptor auditAdminInterceptor) {
        this.auditAdminInterceptor = auditAdminInterceptor;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(auditAdminInterceptor).addPathPatterns("/admin/**");
    }
}
