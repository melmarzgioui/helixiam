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

/** Review rc.3 #1: V16 removes role grants whose user is not a member of the role's realm, keeping valid ones. */
@Testcontainers
class FlywayCrossRealmGrantCleanupTest {

    @Container
    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Test
    void crossRealmGrantsAreRemoved_validGrantsKept() {
        final DriverManagerDataSource ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).locations("classpath:db/migration").target("15").load().migrate();
        final JdbcTemplate jdbc = new JdbcTemplate(ds);
        jdbc.update("INSERT INTO tenant (tenant_id, name) VALUES ('master','master'), ('monthfold','monthfold') ON CONFLICT DO NOTHING");
        jdbc.update("INSERT INTO user_credentials (user_id, username) VALUES ('admin-1','admin'), ('maya-1','maya')");
        jdbc.update("INSERT INTO tenant_user (tenant_user_id, tenant_id, user_id) VALUES ('tu-a','master','admin-1'), ('tu-m','monthfold','maya-1')");
        jdbc.update("INSERT INTO user_roles (role_id, name, tenant_id) VALUES ('r-master-admin','admin','master'), ('r-mf-user','user','monthfold')");
        jdbc.update("INSERT INTO user_in_role (role_id, user_id, tenant_user_id) VALUES "
                + "('r-master-admin','admin-1','tu-a'), ('r-mf-user','maya-1','tu-m'), ('r-master-admin','maya-1','tu-m')");

        Flyway.configure().dataSource(ds).locations("classpath:db/migration").load().migrate();

        assertThat(jdbc.queryForList("SELECT role_id || ':' || user_id FROM user_in_role ORDER BY 1", String.class))
                .containsExactly("r-master-admin:admin-1", "r-mf-user:maya-1");
    }
}
