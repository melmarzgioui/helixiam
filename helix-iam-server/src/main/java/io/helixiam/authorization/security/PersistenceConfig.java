package io.helixiam.authorization.security;

import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

/**
 * Helix IAM (Q4): pluggable OAuth2 authorization (token) store — the publisher holds NO datasource.
 *
 * <p>The backend is selected by {@code helix.iam.token-store} (env {@code HELIX_TOKEN_STORE}):
 * <ul>
 *   <li><b>queue</b> (default) — delegated to the subscriber over AMQP
 *       ({@link QueueOAuth2AuthorizationService}); the publisher needs no database.</li>
 *   <li><b>redis</b> — in-memory + TTL ({@link RedisOAuth2AuthorizationService}) for the
 *       high-throughput tier.</li>
 * </ul>
 * Durable identity data + client secrets live in the subscriber's Postgres, never the publisher.
 */
@Configuration
public class PersistenceConfig {

    /**
     * Default: queue-backed authorization store — the publisher holds NO datasource; persistence is delegated
     * to the subscriber over AMQP ({@code helix.iam.token-store=queue}).
     */
    @Bean
    @ConditionalOnProperty(name = "helix.iam.token-store", havingValue = "queue", matchIfMissing = true)
    public OAuth2AuthorizationService queueAuthorizationService(final AuthorizationStorePublisher store) {
        return new QueueOAuth2AuthorizationService(store);
    }

    /** Opt-in: Redis authorization store for the high-throughput tier. */
    @Bean
    @ConditionalOnProperty(name = "helix.iam.token-store", havingValue = "redis")
    public OAuth2AuthorizationService redisAuthorizationService(
            final RedisConnectionFactory redisConnectionFactory) {
        final RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return new RedisOAuth2AuthorizationService(template);
    }
}
