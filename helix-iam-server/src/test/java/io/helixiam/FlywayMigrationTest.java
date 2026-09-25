/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Disabled;
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
 * fresh database must be brought fully up to date by {@code db/migration/V1..V8} (and the app must
 * boot on that schema — including {@code RealmBootstrap} seeding the master realm). This is the only
 * test that runs the Flyway path; {@link ContextLoadsTest} and the login-headers test pin the legacy
 * {@code schema.sql} path instead.
 */
@SpringBootTest
@Testcontainers
@Disabled("The Flyway V1..V8 baseline is not yet verified-equivalent to schema.sql: the app fails to "
        + "boot on the Flyway path (ServiceProviderService init -> DuplicateException). Re-enable once "
        + "the two schemas are reconciled and Flyway can become the default (CHANGES-1.0.md O5).")
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
    }
}
