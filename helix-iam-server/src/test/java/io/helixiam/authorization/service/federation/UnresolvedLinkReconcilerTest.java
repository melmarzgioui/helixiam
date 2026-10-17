/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.federation;

import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.adminrbac.PrivilegedLegacyLinkReport;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UnresolvedLinkReconcilerTest {

    @Test
    void aRowAnotherReplicaResolvedFirstIsSkipped_andTheRestAreStillResolved() {
        final JdbcTemplate jdbc = mock(JdbcTemplate.class);
        final PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        final UnresolvedLinkReconciler reconciler = new UnresolvedLinkReconciler(jdbc, transactions,
                mock(AuditLog.class), mock(PrivilegedLegacyLinkReport.class));

        when(jdbc.queryForList(anyString(), eq("UNRESOLVED"))).thenReturn(List.of(
                Map.of("id", "acme|clash|1", "realm_id", "acme", "idp_alias", "clash", "external_subject", "1",
                        "user_id", "u1"),
                Map.of("id", "acme|corp|2", "realm_id", "acme", "idp_alias", "corp", "external_subject", "2",
                        "user_id", "u2")));
        when(jdbc.queryForList(anyString(), eq("clash"))).thenReturn(List.of(Map.of("realm_id", "acme", "protocol", "oidc")));
        when(jdbc.queryForList(anyString(), eq("corp"))).thenReturn(List.of(Map.of("realm_id", "acme", "protocol", "oidc")));
        when(jdbc.update(anyString(), eq("acme|clash|1"), eq("acme"), eq("LEGACY"), eq("acme|clash|1"), eq("UNRESOLVED")))
                .thenThrow(new DuplicateKeyException("another replica"));
        when(jdbc.update(anyString(), eq("acme|corp|2"), eq("acme"), eq("LEGACY"), eq("acme|corp|2"), eq("UNRESOLVED")))
                .thenReturn(1);

        final var done = reconciler.reconcile();

        assertThat(done).extracting(UnresolvedLinkReconciler.Resolution::idpAlias).containsExactly("corp");
    }
}
