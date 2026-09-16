package group.mfnr.authorization.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * Helix IAM SSO P4: wires a {@link SessionRegistry} so Spring Authorization Server can mint the OIDC
 * {@code sid} claim (the base64url SHA-256 of the HTTP session id) into id_tokens. {@code sid} is the
 * single key that ties every client authorization in one browser login into one SSO session — the basis
 * for the unified Sessions view and for Single Logout (P5–P9). The {@link HttpSessionEventPublisher}
 * keeps the registry in step with session create/destroy.
 */
@Configuration
public class SessionManagement {

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}
