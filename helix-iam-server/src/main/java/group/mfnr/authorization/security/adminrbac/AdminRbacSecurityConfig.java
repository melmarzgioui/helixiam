package group.mfnr.authorization.security.adminrbac;

import group.mfnr.authorization.amqp.adminrbac.AdminRbacPublisher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Helix IAM: supplies the {@link AdminAuthorizationManager} bean for fine-grained {@code /admin/**} RBAC.
 * <p>
 * Kept in its own {@code @Configuration} (rather than in the contended {@code SecurityConfig}) so the manager
 * can be wired without editing that file. To activate enforcement, {@code SecurityConfig.defaultSecurityFilterChain}
 * must attach this bean to {@code /admin/**} with {@code .access(...)} — see the feature report for the exact,
 * minimal insertion. Until that line is added, this bean is inert (default-safe).
 */
@Configuration
public class AdminRbacSecurityConfig {

    @Bean
    public AdminAuthorizationManager adminAuthorizationManager(
            final AdminRbacPublisher publisher,
            @Value("${helix.admin.dev-open:false}") final boolean adminDevOpen) {
        return new AdminAuthorizationManager(publisher, adminDevOpen);
    }
}
