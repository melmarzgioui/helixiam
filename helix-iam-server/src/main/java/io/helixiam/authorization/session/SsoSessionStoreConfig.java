package io.helixiam.authorization.session;

import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Helix IAM SSO P4: selects the SSO-session reader to match the active OAuth2-authorization (token) store
 * — JDBC by default, Redis when {@code helix.iam.token-store=redis} (the high-throughput tier). Mirrors
 * {@code PersistenceConfig}; the Redis template uses the same key/value serialization as
 * {@code RedisOAuth2AuthorizationService} so it deserializes the stored authorizations.
 */
@Configuration
public class SsoSessionStoreConfig {

    // Redis is declared FIRST so the JDBC default's @ConditionalOnMissingBean sees it when token-store=redis.
    @Bean
    @ConditionalOnProperty(name = "helix.iam.token-store", havingValue = "redis")
    public SsoSessionStore redisSsoSessionStore(final RedisConnectionFactory redisConnectionFactory) {
        final RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new JdkSerializationRedisSerializer());
        template.afterPropertiesSet();
        return new RedisSsoSessionStore(template);
    }

    /** Default SSO reader — rolls up the authorizations from the subscriber over AMQP (token-store=queue). */
    @Bean
    @ConditionalOnMissingBean(SsoSessionStore.class)
    public SsoSessionStore queueSsoSessionStore(final AuthorizationStorePublisher store) {
        return new QueueSsoSessionStore(store);
    }
}
