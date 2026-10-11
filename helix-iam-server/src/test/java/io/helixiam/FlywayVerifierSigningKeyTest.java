/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Task 5: V76 creates {@code verifier_signing_key} (the OpenID4VP verifier access-certificate keys), keyed by
 * {@code (realm_id, name)}: the same name may exist once per realm.
 */
@Testcontainers
class FlywayVerifierSigningKeyTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void v76_createsTable_withRealmNamePrimaryKey() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("76").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        final String insert = "INSERT INTO verifier_signing_key (realm_id, name, alg, private_key, certificate_chain_pem)"
                + " VALUES (?, 'access', 'ES256', 'enc', 'PEM')";
        jdbc.update(insert, "a");
        jdbc.update(insert, "b");
        assertThatThrownBy(() -> jdbc.update(insert, "a")).isInstanceOf(DuplicateKeyException.class);
        assertThat(jdbc.queryForObject("SELECT created_at IS NOT NULL FROM verifier_signing_key WHERE realm_id = 'a'",
                Boolean.class)).isTrue();
    }
}
