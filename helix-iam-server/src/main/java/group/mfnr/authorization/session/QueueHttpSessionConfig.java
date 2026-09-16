package group.mfnr.authorization.session;

import group.mfnr.authorization.amqp.httpsession.HttpSessionStorePublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.MapSession;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

import java.time.Duration;

/**
 * Helix IAM (Q3): activates the queue-backed Spring Session {@link FindByIndexNameSessionRepository} when
 * {@code helix.iam.session-store=queue}, so HTTP login sessions persist to the subscriber and the publisher
 * needs no datasource. {@code QueueSessionEnvironmentPostProcessor} sets {@code spring.session.store-type=none}
 * in this mode so Boot's JDBC/Redis session auto-config backs off and only this repository is used.
 */
@Configuration
@EnableSpringHttpSession
@ConditionalOnProperty(name = "helix.iam.session-store", havingValue = "queue")
public class QueueHttpSessionConfig {

    @Bean
    public FindByIndexNameSessionRepository<MapSession> sessionRepository(
            final HttpSessionStorePublisher store,
            @Value("${server.servlet.session.timeout:30m}") final Duration timeout) {
        return new QueueIndexedSessionRepository(store, timeout);
    }
}
