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

/** V17: every user gets a home realm, and usernames/emails become unique per realm on an existing install. */
@Testcontainers
class FlywayUsernamePerRealmTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void backfillsHomeRealms_andAllowsTheSameUsernameInAnotherRealm() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("16").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('master','master'), ('firm-a','firm-a') ON CONFLICT DO NOTHING");
        jdbc.update("INSERT INTO user_credentials (user_id, username, email, password) VALUES "
                + "('u-admin','admin',NULL,'x'), ('u-joe','joe','joe@shared.example','x'), "
                + "('u-selfreg','ann@example.com','ann@example.com','x'), ('u-jit','fed@example.com','fed@example.com',NULL)");
        jdbc.update("INSERT INTO tenant_user (tenant_user_id, tenant_id, user_id) VALUES ('t1','master','u-admin'), ('t2','firm-a','u-joe')");

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        assertThat(realmOf(jdbc, "u-admin")).isEqualTo("master");
        assertThat(realmOf(jdbc, "u-joe")).isEqualTo("firm-a");
        assertThat(realmOf(jdbc, "u-selfreg")).as("self-registered before 1.0").isEqualTo("master");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM tenant_user WHERE user_id = 'u-selfreg' AND tenant_id = 'master'",
                Integer.class)).isEqualTo(1);
        assertThat(realmOf(jdbc, "u-jit")).as("federated JIT user without a password").isNull();

        // The same username and email can now exist in another realm, but not twice in one.
        jdbc.update("INSERT INTO user_credentials (user_id, username, email, realm_id) VALUES ('u-joe-m','joe','joe@shared.example','master')");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM user_credentials WHERE username = 'joe'", Integer.class)).isEqualTo(2);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> jdbc.update(
                "INSERT INTO user_credentials (user_id, username, realm_id) VALUES ('u-joe-2','joe','firm-a')"))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
    }

    private static String realmOf(final JdbcTemplate jdbc, final String userId) {
        return jdbc.queryForObject("SELECT realm_id FROM user_credentials WHERE user_id = ?", String.class, userId);
    }
}
