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
 * 1.0 item 8: V13 renames an existing install's {@code kubedna-cli} client to {@code helix-cli} (keeping its id, so
 * grants stay valid) and disables the formerly seeded demo client {@code oidc-client}. Runs the real migrations:
 * up to V12, seed rc-era data, then to the latest version.
 */
@Testcontainers
class FlywayRenameMigrationTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void renamesTheCliClientAndDisablesTheDemoClient() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("12").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('master', 'master'), ('monthfold', 'monthfold') "
                + "ON CONFLICT DO NOTHING");
        insertClient(jdbc, "cli-1", "kubedna-cli", "master", "master", "");
        insertClient(jdbc, "cli-2", "kubedna-cli", "monthfold", "monthfold", "");
        insertClient(jdbc, "cli-3", "helix-cli", "monthfold", "monthfold", ""); // already has the new one
        insertClient(jdbc, "demo", "oidc-client", "-1234", "master", "https://dashboard.kubedna.io/login/oauth2/code/kube");

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        assertThat(jdbc.queryForObject("SELECT client_id FROM service_provider_oauth WHERE service_provider_id = 'cli-1'",
                String.class)).isEqualTo("helix-cli");
        assertThat(jdbc.queryForObject("SELECT name FROM service_provider_oauth WHERE service_provider_id = 'cli-1'",
                String.class)).isEqualTo("HelixIAM CLI");
        assertThat(jdbc.queryForObject("SELECT deleted FROM service_provider_oauth WHERE service_provider_id = 'cli-2'",
                Boolean.class)).isTrue();
        assertThat(jdbc.queryForObject("SELECT deleted FROM service_provider_oauth WHERE service_provider_id = 'cli-3'",
                Boolean.class)).isFalse();
        assertThat(jdbc.queryForObject("SELECT deleted FROM service_provider_oauth WHERE service_provider_id = 'demo'",
                Boolean.class)).isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM service_provider_oauth WHERE client_id = 'kubedna-cli' "
                + "AND deleted = false", Integer.class)).isZero();
    }

    private static void insertClient(final JdbcTemplate jdbc, final String id, final String clientId, final String tenant,
                                     final String realm, final String redirectUris) {
        jdbc.update("INSERT INTO service_provider_oauth (service_provider_id, client_id, client_id_issued_at, tenant_id, "
                + "realm_id, authorization_grant_types, redirect_uris, scopes, deleted) VALUES (?, ?, now(), ?, ?, "
                + "'authorization_code', ?, 'openid', false)", id, clientId, tenant, realm, redirectUris);
    }
}
