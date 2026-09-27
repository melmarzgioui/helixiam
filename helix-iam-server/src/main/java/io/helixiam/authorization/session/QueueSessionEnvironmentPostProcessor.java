/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

/**
 * Helix IAM (Q3): when the HTTP session store is the queue ({@code HELIX_SESSION_STORE=queue}), force
 * {@code spring.session.store-type=none} so Boot's JDBC/Redis session auto-configuration backs off and the
 * queue-backed {@code QueueIndexedSessionRepository} ({@link QueueHttpSessionConfig}) is the only session
 * store. (Boot's {@code StoreType} enum has no "queue" value, so it cannot be set there directly.) Reads the
 * raw {@code HELIX_SESSION_STORE} env var so it is reliable regardless of property-source ordering.
 *
 * <p>C4: when Redis is neither the session store nor the token store ({@code HELIX_TOKEN_STORE=redis}), the Redis
 * health indicators — the imperative and the reactive one, both keyed {@code management.health.redis.enabled} — are
 * switched off, so {@code /actuator/health} is not DOWN for a Redis that is not used. An explicit
 * {@code management.health.redis.enabled} setting always wins. Registered in {@code META-INF/spring.factories}
 * (Boot 3 does not read an {@code .imports} file for post-processors).
 */
public class QueueSessionEnvironmentPostProcessor implements EnvironmentPostProcessor {

    static final String REDIS_HEALTH = "management.health.redis.enabled";

    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment environment, final SpringApplication application) {
        final String store = environment.getProperty("HELIX_SESSION_STORE",
                environment.getProperty("helix.iam.session-store", "redis"));
        final String tokenStore = environment.getProperty("HELIX_TOKEN_STORE",
                environment.getProperty("helix.iam.token-store", "queue"));
        final Map<String, Object> overrides = new HashMap<>();
        if ("queue".equalsIgnoreCase(store)) {
            overrides.put("spring.session.store-type", "none");
            overrides.put("helix.iam.session-store", "queue");
        }
        final boolean redisUsed = "redis".equalsIgnoreCase(store) || "redis".equalsIgnoreCase(tokenStore);
        if (!redisUsed && environment.getProperty(REDIS_HEALTH) == null) {
            overrides.put(REDIS_HEALTH, "false"); // Redis is not used, so it must not make /actuator/health DOWN
        }
        if (!overrides.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource("helix-queue-session", overrides));
        }
    }
}
