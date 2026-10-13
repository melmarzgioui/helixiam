/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Production readiness item 1: V78 creates {@code idp_config_version}, one row per realm; the repository's bump (an
 * upsert) starts a realm at 1 and adds one per write.
 */
@Testcontainers
class FlywayIdpConfigVersionTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void v78_createsTheTable_andTheBumpUpsertCounts() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("78").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        final String bump = "INSERT INTO idp_config_version (realm_id, version, updated_at) VALUES (?, 1, CURRENT_TIMESTAMP)"
                + " ON CONFLICT (realm_id) DO UPDATE SET version = idp_config_version.version + 1,"
                + " updated_at = CURRENT_TIMESTAMP";
        jdbc.update(bump, "a");
        jdbc.update(bump, "a");
        jdbc.update(bump, "b");

        assertThat(jdbc.queryForObject("SELECT version FROM idp_config_version WHERE realm_id = 'a'", Long.class))
                .isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT version FROM idp_config_version WHERE realm_id = 'b'", Long.class))
                .isEqualTo(1);
    }
}
