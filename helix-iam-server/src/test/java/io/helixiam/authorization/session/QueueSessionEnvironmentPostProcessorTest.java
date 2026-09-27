/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.mock.env.MockEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/** With PostgreSQL sessions Redis is unused, so its health indicator must not report the service DOWN. */
class QueueSessionEnvironmentPostProcessorTest {

    @Test
    void postgresSessions_disableTheRedisHealthIndicator() {
        final MockEnvironment env = new MockEnvironment().withProperty("helix.iam.session-store", "queue");
        new QueueSessionEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        assertThat(env.getProperty("management.health.redis.enabled")).isEqualTo("false");
    }

    @Test
    void redisSessions_keepTheRedisHealthIndicator() {
        final MockEnvironment env = new MockEnvironment().withProperty("helix.iam.session-store", "redis");
        new QueueSessionEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        assertThat(env.getProperty("management.health.redis.enabled")).isNull();
    }
}
