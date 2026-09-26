/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises the production schema path: Flyway is the default in {@code application.properties}, so a
 * fresh database must be brought fully up to date by {@code db/migration/V*} (and the app must
 * boot on that schema — including {@code RealmBootstrap} seeding the master realm). The e2e suite also runs
 * on Flyway by default; {@link ContextLoadsTest} and the login-headers test pin the legacy
 * {@code schema.sql} path.
 */
@SpringBootTest
@Testcontainers
class FlywayMigrationTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("helixiam")
                    .withUsername("helixiam")
                    .withPassword("helixiam");

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.readonly.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("database.encryption", () -> "0123456789abcdef0123456789abcdef");
        registry.add("idp.base.url", () -> "http://localhost:8080");
        registry.add("sp.base.url", () -> "http://localhost:8090");
        // Force the Flyway path explicitly (this is also the shipped default).
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.sql.init.mode", () -> "never");
        registry.add("spring.session.store-type", () -> "none");
        registry.add("helix.iam.session-store", () -> "queue"); // no Redis in this test: PostgreSQL sessions
    }

    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void flywayBringsUpTheSchemaAndTheAppBoots() {
        final Integer applied = jdbc.queryForObject(
                "SELECT count(*) FROM flyway_schema_history WHERE success = true", Integer.class);
        assertThat(applied).as("Flyway migrations applied").isNotNull().isGreaterThanOrEqualTo(8);

        // RealmBootstrap must have seeded the master realm (a tenant) on the Flyway-built schema.
        final Integer masterRealms = jdbc.queryForObject(
                "SELECT count(*) FROM tenant WHERE tenant_id = 'master' OR name = 'master'", Integer.class);
        assertThat(masterRealms).as("master realm seeded").isGreaterThanOrEqualTo(1);

        // 1.0 item 8: no demo client with a known secret, and the CLI client carries the HelixIAM name.
        assertThat(jdbc.queryForObject("SELECT count(*) FROM service_provider_oauth WHERE client_id = 'oidc-client' "
                + "AND deleted = false", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM service_provider_oauth WHERE client_id = 'kubedna-cli'",
                Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM service_provider_oauth WHERE client_id = 'helix-cli' "
                + "AND realm_id = 'master' AND deleted = false", Integer.class)).isEqualTo(1);
    }
}
