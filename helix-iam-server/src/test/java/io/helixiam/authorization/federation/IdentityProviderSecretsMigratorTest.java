/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.persistence.security.AttributeEncryption;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Merge of the wallet and security branches (final review M5/D): an undecryptable {@code secret_json} now throws from
 * {@link AttributeEncryption} (fail closed) instead of coming back unchanged. The backfill reads each row's stored
 * secrets on its own, so one unreadable row is logged by id and skipped — it must not abort the backfill of the others.
 */
class IdentityProviderSecretsMigratorTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";

    @Test
    void oneUnreadableRow_isSkipped_andTheOthersAreStillMoved() throws Exception {
        final AttributeEncryption encryption = new AttributeEncryption(KEY);
        final Connection connection = mock(Connection.class);
        final PreparedStatement select = mock(PreparedStatement.class);
        final ResultSet rows = mock(ResultSet.class);
        when(connection.prepareStatement(startsWith("SELECT"))).thenReturn(select);
        when(select.executeQuery()).thenReturn(rows);
        when(rows.next()).thenReturn(true, true, false);
        // row 1: legacy secret in config_json and a secret_json no key can read; row 2: a legacy secret only
        when(rows.getString(1)).thenReturn("gov|broken", "gov|ok");
        when(rows.getString(2)).thenReturn("oidc", "oidc");
        when(rows.getString(3)).thenReturn("{\"clientId\":\"a\",\"clientSecret\":\"s1\"}",
                "{\"clientId\":\"b\",\"clientSecret\":\"s2\"}");
        when(rows.getString(4)).thenReturn("bm90LWEtY2lwaGVydGV4dA==", (String) null);
        final PreparedStatement update = mock(PreparedStatement.class);
        when(connection.prepareStatement(startsWith("UPDATE"))).thenReturn(update);
        final List<String> updatedIds = new ArrayList<>();
        final String[] lastId = new String[1];
        doAnswer(inv -> {
            if ((int) inv.getArgument(0) == 3) {
                lastId[0] = inv.getArgument(1);
            }
            return null;
        }).when(update).setString(anyInt(), anyString());
        when(update.executeUpdate()).thenAnswer(inv -> {
            updatedIds.add(lastId[0]);
            return 1;
        });

        final int moved = new IdentityProviderSecretsMigrator(encryption).migrate(connection);

        assertThat(moved).isEqualTo(1);
        assertThat(updatedIds).containsExactly("gov|ok");
    }
}
