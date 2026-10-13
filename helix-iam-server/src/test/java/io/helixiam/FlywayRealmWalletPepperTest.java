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
 * Task 21a: V77 creates {@code realm_wallet_pepper} (the per-realm wallet-subject HMAC pepper), one row per realm; a
 * second insert for the same realm is a no-op under {@code ON CONFLICT DO NOTHING} (the race-safe creation path).
 */
@Testcontainers
class FlywayRealmWalletPepperTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void v77_createsTable_oneRowPerRealm() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("77").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);

        final String insert = "INSERT INTO realm_wallet_pepper (realm_id, pepper) VALUES (?, ?)"
                + " ON CONFLICT (realm_id) DO NOTHING";
        assertThat(jdbc.update(insert, "a", "first")).isEqualTo(1);
        assertThat(jdbc.update(insert, "b", "other")).isEqualTo(1);
        assertThat(jdbc.update(insert, "a", "second")).isZero();
        assertThat(jdbc.queryForObject("SELECT pepper FROM realm_wallet_pepper WHERE realm_id = 'a'", String.class))
                .isEqualTo("first");
        assertThat(jdbc.queryForObject("SELECT created_at IS NOT NULL FROM realm_wallet_pepper WHERE realm_id = 'a'",
                Boolean.class)).isTrue();
    }
}
