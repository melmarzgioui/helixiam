package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.httpsession.HttpSessionStorePublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Helix IAM (Q4): the cascading-logout {@link SpringSessionStore} — queue-backed (deletes a principal's HTTP
 * sessions from the subscriber over AMQP). The publisher has no datasource.
 */
@Configuration
public class SpringSessionStoreConfig {

    @Bean
    public SpringSessionStore queueSpringSessionStore(final HttpSessionStorePublisher store) {
        return new QueueSpringSessionStore(store);
    }
}
