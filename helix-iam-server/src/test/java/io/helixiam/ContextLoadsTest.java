/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Strip-RabbitMQ migration, Task 5: proves the merged HelixIAM context (former
 * OAuth2/OIDC/SAML web front + identity domain, no broker) starts as a single standalone app.
 *
 * <p>Backing store: a throwaway Postgres via Testcontainers (Docker required) wired into the
 * single {@code spring.datasource.*} the merged app expects; {@code schema.sql} runs against it
 * via {@code spring.sql.init}. The read-only URL is pointed at the same container so the routing
 * datasource's fallback pool is reachable.
 *
 * <p>Redis: kept in the main config, but HTTP-session persistence is switched off FOR THIS TEST
 * only ({@code spring.session.store-type=none}) so context load does not need a live Redis — the
 * OAuth2 token store defaults to the in-process, Postgres-backed adapter path, which needs no Redis.
 */
@SpringBootTest
@Testcontainers
class ContextLoadsTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("kubeiam")
                    .withUsername("kubeiam")
                    .withPassword("kubeiam");

    @DynamicPropertySource
    static void datasourceProperties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        // Point the routing datasource's read-only fallback at the same container.
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);

        // The at-rest attribute-encryption key has no shipped default (H1) — provide a test key
        // so the context loads (the app correctly fail-fasts when this is unset).
        registry.add("database.encryption", () -> "0123456789abcdef0123456789abcdef");

        // Schema via schema.sql (default path); keep Flyway off for the test.
        registry.add("spring.sql.init.mode", () -> "always");
        registry.add("spring.flyway.enabled", () -> "false");

        // Do not require a live Redis for a context-load test (Redis stays in the main config).
        registry.add("spring.session.store-type", () -> "none");
    }

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoads() {
        assertThat(context).isNotNull();
        assertThat(context.getBeanDefinitionCount()).isPositive();
    }
}
