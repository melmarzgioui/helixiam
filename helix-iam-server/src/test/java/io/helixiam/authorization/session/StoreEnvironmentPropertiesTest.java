/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;

import java.util.Map;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item 5: the Helm chart selects the stores with {@code HELIX_SESSION_STORE} and {@code HELIX_TOKEN_STORE}. Both must
 * reach the properties the beans are selected by ({@code helix.iam.session-store}, {@code helix.iam.token-store}); an
 * env var named {@code HELIX_TOKEN_STORE} alone binds to {@code helix.token.store}, which nothing reads.
 */
class StoreEnvironmentPropertiesTest {

    private static StandardEnvironment envWith(final Map<String, Object> env) throws Exception {
        final Properties props = new Properties();
        try (var in = new ClassPathResource("application.properties").getInputStream()) {
            props.load(in);
        }
        final StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("env", env));
        environment.getPropertySources().addLast(new PropertiesPropertySource("app", props));
        return environment;
    }

    @Test
    void theDefaults_areRedisSessions_andTheQueueTokenStore() throws Exception {
        final StandardEnvironment env = envWith(Map.of());
        assertThat(env.getProperty("helix.iam.session-store")).isEqualTo("redis");
        assertThat(env.getProperty("helix.iam.token-store")).isEqualTo("queue");
    }

    @Test
    void theEnvVars_selectTheStores() throws Exception {
        final StandardEnvironment env = envWith(Map.of("HELIX_SESSION_STORE", "queue", "HELIX_TOKEN_STORE", "redis"));
        assertThat(env.getProperty("helix.iam.session-store")).isEqualTo("queue");
        assertThat(env.getProperty("helix.iam.token-store")).isEqualTo("redis");
    }
}
