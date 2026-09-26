/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Component;

/**
 * 1.0 operational note: with the default HTTP-session store (Redis) an unreachable Redis used to surface only at
 * the first sign-in, as a 500 on {@code /oauth2/authorize}. Fail at startup instead, with a message that says
 * what to do. Disable with {@code helix.iam.redis-startup-check=false} (e.g. when Redis starts after HelixIAM).
 */
@Component
@ConditionalOnProperty(name = "helix.iam.session-store", havingValue = "redis")
public class RedisStartupCheck implements SmartInitializingSingleton {

    private final RedisConnectionFactory redis;
    private final boolean enabled;
    private final String host;
    private final int port;

    public RedisStartupCheck(final RedisConnectionFactory redis,
                             @Value("${helix.iam.redis-startup-check:true}") final boolean enabled,
                             @Value("${spring.data.redis.host:localhost}") final String host,
                             @Value("${spring.data.redis.port:6379}") final int port) {
        this.redis = redis;
        this.enabled = enabled;
        this.host = host;
        this.port = port;
    }

    @Override
    public void afterSingletonsInstantiated() {
        if (!enabled) {
            return;
        }
        try (RedisConnection connection = redis.getConnection()) {
            connection.ping();
        } catch (final RuntimeException e) {
            throw new IllegalStateException("HelixIAM keeps HTTP sessions in Redis (HELIX_SESSION_STORE=redis) but "
                    + "cannot reach Redis at " + host + ":" + port + " (" + e.getMessage() + "). Start Redis or set "
                    + "REDIS_HOST/REDIS_PORT, or set HELIX_SESSION_STORE=queue to keep sessions in PostgreSQL.", e);
        }
    }
}
