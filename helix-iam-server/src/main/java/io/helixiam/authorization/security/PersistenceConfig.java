/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.amqp.authzstore.AuthorizationStorePublisher;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
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
        // A3: bind each issued code to the browser SSO session (sid + auth_time) for the ID token claims.
        return new io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService(
                new QueueOAuth2AuthorizationService(store));
    }

    /**
     * The Redis template of the token store: string keys, Java-serialized values read through the token store's
     * JEP-290 allowlist (as the queue store's blobs); a refused or unreadable entry is absent. Also reads authorizations
     * written by 1.0 (Spring Authorization Server 1.5).
     */
    public static RedisTemplate<String, Object> authorizationTemplate(final RedisConnectionFactory redisConnectionFactory) {
        final RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(FilteredJdkRedisSerializer.forAuthorizations());
        template.afterPropertiesSet();
        return template;
    }

    /** Opt-in: Redis authorization store for the high-throughput tier. */
    @Bean
    @ConditionalOnProperty(name = "helix.iam.token-store", havingValue = "redis")
    public OAuth2AuthorizationService redisAuthorizationService(
            final RedisConnectionFactory redisConnectionFactory) {
        final RedisTemplate<String, Object> template = authorizationTemplate(redisConnectionFactory);
        return new io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService(
                new RedisOAuth2AuthorizationService(template));
    }
}
