/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * deploy/scripts/factor-roles-check.sql, the pre-upgrade check in docs/UPGRADING.md, finds every legacy role in the
 * reserved FACTOR_ namespace (any case: realm, client, service-account and agent roles) and nothing else. Runs the file
 * itself against the real schema.
 */
class FactorRolesCheckQueryE2eTest extends AbstractE2eTest {

    @Test
    void theQueryListsEveryLegacyFactorRole_andNoOtherRole() throws Exception {
        final String realm = E2eSeed.unique("factorcheck");
        seed().realm(realm);
        final JdbcTemplate jdbc = new JdbcTemplate(context.getBean(DataSource.class));
        new org.springframework.transaction.support.TransactionTemplate(
                context.getBean(org.springframework.transaction.PlatformTransactionManager.class)).executeWithoutResult(tx -> {
        jdbc.update("insert into user_roles (role_id, name, tenant_id) values (?, ?, ?)", id(), "FACTOR_PASSWORD", realm);
        jdbc.update("insert into user_roles (role_id, name, tenant_id) values (?, ?, ?)", id(), "factorless", realm);
        jdbc.update("insert into client_role (role_id, realm_id, client_id, name) values (?, ?, ?, ?)", id(), realm, "web",
                "Factor_Ott");
        jdbc.update("insert into client_service_account_role (id, realm_id, client_id, role_name) values (?, ?, ?, ?)",
                id(), realm, "ledger", "FACTOR_X");
        jdbc.update("insert into agent_identity (id, realm_id, name, owner, roles) values (?, ?, ?, ?, ?)", id(), realm,
                "bot-a", "ada", "reader, billing/FACTOR_Y");
        jdbc.update("insert into agent_identity (id, realm_id, name, owner, roles) values (?, ?, ?, ?, ?)", id(), realm,
                "bot-b", "ada", "reader, myfactor_role");
        });

        final String sql = Files.readString(Path.of("..", "deploy", "scripts", "factor-roles-check.sql"))
                .replaceAll("(?m)^--.*$", "").trim().replaceAll(";$", "");
        final List<Map<String, Object>> rows = jdbc.queryForList(sql).stream()
                .filter(row -> realm.equals(row.get("realm"))).toList();

        assertThat(rows).extracting(row -> row.get("kind") + ":" + row.get("role")).containsExactlyInAnyOrder(
                "realm role:FACTOR_PASSWORD", "client role:Factor_Ott", "service-account role:FACTOR_X",
                "agent role:reader, billing/FACTOR_Y");
    }

    private static String id() {
        return UUID.randomUUID().toString();
    }
}
