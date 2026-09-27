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

    @Test
    void aRedisTokenStore_keepsTheRedisHealthIndicator() {
        final MockEnvironment env = new MockEnvironment().withProperty("helix.iam.session-store", "queue")
                .withProperty("helix.iam.token-store", "redis");
        new QueueSessionEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        assertThat(env.getProperty("management.health.redis.enabled")).isNull();
    }

    @Test
    void anExplicitSetting_wins() {
        final MockEnvironment env = new MockEnvironment().withProperty("helix.iam.session-store", "queue")
                .withProperty("management.health.redis.enabled", "true");
        new QueueSessionEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        assertThat(env.getProperty("management.health.redis.enabled")).isEqualTo("true");
    }

    @Test
    void theHelmEnvVariable_selectsTheStore() {
        final MockEnvironment env = new MockEnvironment().withProperty("HELIX_SESSION_STORE", "queue")
                .withProperty("helix.iam.session-store", "redis");
        new QueueSessionEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        assertThat(env.getProperty("management.health.redis.enabled")).isEqualTo("false");
        assertThat(env.getProperty("helix.iam.session-store")).isEqualTo("queue");
    }

    @Test
    void isRegisteredSoBootActuallyRunsIt() {
        // C4: Boot 3 reads post-processors from spring.factories; the former .imports file was silently ignored.
        assertThat(org.springframework.core.io.support.SpringFactoriesLoader.loadFactoryNames(
                org.springframework.boot.env.EnvironmentPostProcessor.class, getClass().getClassLoader()))
                .contains(QueueSessionEnvironmentPostProcessor.class.getName());
    }
}
