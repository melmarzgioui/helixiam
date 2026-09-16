package group.mfnr.authorization.observability;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Helix IAM observability: registers the {@link MetricsAdminInterceptor} on {@code /admin/**}. Kept separate
 * from the audit web config so this feature is self-contained and adds no per-controller code.
 */
@Configuration
public class MetricsWebConfig implements WebMvcConfigurer {

    private final MetricsAdminInterceptor metricsAdminInterceptor;

    public MetricsWebConfig(final MetricsAdminInterceptor metricsAdminInterceptor) {
        this.metricsAdminInterceptor = metricsAdminInterceptor;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(metricsAdminInterceptor).addPathPatterns("/admin/**");
    }
}
