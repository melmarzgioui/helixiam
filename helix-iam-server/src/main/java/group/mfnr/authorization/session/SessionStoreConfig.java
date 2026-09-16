package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Helix IAM (Q4): the Sessions-admin {@link SessionStore} reader — queue-backed (reads the realm's
 * authorizations from the subscriber over AMQP). The publisher has no datasource.
 */
@Configuration
public class SessionStoreConfig {

    @Bean
    public SessionStore queueSessionStore(final AuthorizationStorePublisher store) {
        return new QueueSessionStore(store);
    }
}
