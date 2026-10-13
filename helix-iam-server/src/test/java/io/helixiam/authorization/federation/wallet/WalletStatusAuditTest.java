/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * A wallet login let through without a revocation check (FAIL_OPEN_WITH_AUDIT, the status list transiently
 * unavailable) is audited with the wallet transaction it belongs to, so an operator can tie the fail-open to that login.
 */
class WalletStatusAuditTest {

    private static AuditEvent emitted(final AuditLog log) {
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(log).emit(event.capture());
        return event.getValue();
    }

    @Test
    void theFailOpenAudit_carriesTheTransactionOfTheVerificationItHappenedIn() {
        final AuditLog log = mock(AuditLog.class);

        WalletStatusAudit.duringTransaction("tx-42", () -> {
            WalletStatusAudit.sink(log).statusUnavailableAccepted("status.example",
                    WalletErrorCode.STATUS_UNAVAILABLE, "timeout");
            return null;
        });

        final AuditEvent event = emitted(log);
        assertThat(event.type()).isEqualTo("WALLET_STATUS_CHECK_FAILED");
        assertThat(event.category()).isEqualTo(AuditEvent.AUTHN);
        assertThat(event.detail()).containsEntry("transactionId", "tx-42")
                .containsEntry("statusListHost", "status.example")
                .containsEntry("reason", "wallet.status_unavailable")
                .containsEntry("decision", "FAIL_OPEN_WITH_AUDIT");
    }

    @Test
    void outsideAVerification_thereIsNoTransaction() {
        final AuditLog log = mock(AuditLog.class);

        WalletStatusAudit.sink(log).statusUnavailableAccepted("status.example", WalletErrorCode.STATUS_UNAVAILABLE, "x");

        assertThat(emitted(log).detail()).doesNotContainKey("transactionId");
    }

    @Test
    void theTransactionNeverOutlivesItsVerification_evenWhenItFails() {
        assertThatThrownBy(() -> WalletStatusAudit.duringTransaction("tx-1", () -> {
            throw new IllegalStateException("verification failed");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(WalletStatusAudit.currentTransaction()).isNull();
    }
}
