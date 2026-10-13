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
 * V80: DCR stored {@code private_key_jwt} (RFC 7591 spelling) while the token endpoint reads
 * {@code PRIVATE_KEY_JWT}, so those clients silently authenticated with a secret. The migration stores the spelling
 * the token endpoint reads; other values are left alone.
 */
@Testcontainers
class FlywayPrivateKeyJwtNormalizationTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void lowercasePrivateKeyJwtIsStoredAsTheTokenEndpointReadsIt() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("79").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('t1','t1') ON CONFLICT DO NOTHING");
        final String insert = "INSERT INTO service_provider_oauth (service_provider_id, client_id, tenant_id,"
                + " token_endpoint_auth_method, jwks_url) VALUES (?, ?, 't1', ?, ?)";
        jdbc.update(insert, "1", "dcr-a", "private_key_jwt", "https://a.example/jwks");
        jdbc.update(insert, "2", "dcr-b", "private_key_jwt", null);
        jdbc.update(insert, "3", "admin-c", "PRIVATE_KEY_JWT", "https://c.example/jwks");
        jdbc.update(insert, "4", "dcr-d", "client_secret_basic", null);

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        assertThat(jdbc.queryForList("SELECT client_id || ':' || coalesce(token_endpoint_auth_method, '-')"
                + " FROM service_provider_oauth ORDER BY service_provider_id", String.class))
                .containsExactly("dcr-a:PRIVATE_KEY_JWT", "dcr-b:PRIVATE_KEY_JWT", "admin-c:PRIVATE_KEY_JWT",
                        "dcr-d:client_secret_basic");
    }
}
