/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.mock.env.MockEnvironment;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Kubernetes injects {@code REDIS_PORT=tcp://<ip>:<port>} into every pod of a namespace with a Service named
 * {@code redis} (service links). The server reads {@code REDIS_PORT} as the Redis port, so it takes the port from that
 * form; a plain port and an unset variable are left alone.
 */
class RedisServiceLinkEnvironmentPostProcessorTest {

    private static String redisPortAfter(final MockEnvironment env) {
        new RedisServiceLinkEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        return env.resolvePlaceholders("${REDIS_PORT:6379}");
    }

    @Test
    void theServiceLinkForm_givesItsPort() {
        assertThat(redisPortAfter(new MockEnvironment().withProperty("REDIS_PORT", "tcp://10.43.13.59:6379")))
                .isEqualTo("6379");
        assertThat(redisPortAfter(new MockEnvironment().withProperty("REDIS_PORT", "tcp://10.43.13.59:6380")))
                .isEqualTo("6380");
        assertThat(redisPortAfter(new MockEnvironment().withProperty("REDIS_PORT", "tcp://[fd00::1]:7000")))
                .isEqualTo("7000");
    }

    @Test
    void aPlainPortOrNoValue_isUnchanged() {
        assertThat(redisPortAfter(new MockEnvironment().withProperty("REDIS_PORT", "6390"))).isEqualTo("6390");
        assertThat(redisPortAfter(new MockEnvironment())).isEqualTo("6379");
    }

    @Test
    void theShippedConfiguration_bindsTheParsedPort() {
        final MockEnvironment env = new MockEnvironment().withProperty("REDIS_PORT", "tcp://10.43.13.59:6381");
        env.getPropertySources().addLast(new MapPropertySource("application",
                Map.of("spring.data.redis.port", "${REDIS_PORT:6379}")));
        new RedisServiceLinkEnvironmentPostProcessor().postProcessEnvironment(env, new SpringApplication());
        assertThat(env.getProperty("spring.data.redis.port", Integer.class)).isEqualTo(6381);
    }

    @Test
    void isRegisteredSoBootActuallyRunsIt() {
        assertThat(org.springframework.core.io.support.SpringFactoriesLoader.loadFactoryNames(
                org.springframework.boot.EnvironmentPostProcessor.class, getClass().getClassLoader()))
                .contains(RedisServiceLinkEnvironmentPostProcessor.class.getName());
    }
}
