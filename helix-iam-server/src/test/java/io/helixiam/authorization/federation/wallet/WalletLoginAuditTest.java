/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.security.audit.AuditEvent;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Task 22: the {@code WALLET_LOGIN_SUCCESS} / {@code WALLET_LOGIN_FAILURE} audit event shape. */
class WalletLoginAuditTest {

    @Test
    void success_carriesExactlyTheKnownFields_neverAReason() {
        final AuditEvent event = WalletLoginAudit.success("acme", "user-7", "tx-1", "eudi-wallet", "dc+sd-jwt",
                "CN=Issuer");

        assertThat(event.type()).isEqualTo("WALLET_LOGIN_SUCCESS");
        assertThat(event.category()).isEqualTo(AuditEvent.AUTHN);
        assertThat(event.realm()).isEqualTo("acme");
        assertThat(event.actor()).isEqualTo("user-7");
        assertThat(event.outcome()).isEqualTo("SUCCESS");
        assertThat(event.detail()).containsOnly(
                org.assertj.core.api.Assertions.entry("transactionId", "tx-1"),
                org.assertj.core.api.Assertions.entry("alias", "eudi-wallet"),
                org.assertj.core.api.Assertions.entry("format", "dc+sd-jwt"),
                org.assertj.core.api.Assertions.entry("issuerDn", "CN=Issuer"),
                org.assertj.core.api.Assertions.entry("result", "SUCCESS"));
    }

    @Test
    void failure_carriesTheErrorCodeNameAsReason_andAnonymousActor() {
        final AuditEvent event = WalletLoginAudit.failure("acme", "tx-1", "eudi-wallet", "dc+sd-jwt", "CN=Issuer",
                WalletErrorCode.ISSUER_UNTRUSTED);

        assertThat(event.type()).isEqualTo("WALLET_LOGIN_FAILURE");
        assertThat(event.actor()).isEqualTo("anonymous");
        assertThat(event.outcome()).isEqualTo("FAILURE");
        assertThat(event.detail()).containsEntry("reason", "ISSUER_UNTRUSTED").containsEntry("result", "FAILURE");
    }

    @Test
    void unknownFields_areLeftOut_neverAPlaceholder() {
        final AuditEvent event = WalletLoginAudit.failure("acme", null, "eudi-wallet", null, null,
                WalletErrorCode.REPLAY);

        assertThat(event.detail()).doesNotContainKey("transactionId").doesNotContainKey("format")
                .doesNotContainKey("issuerDn").containsEntry("reason", "REPLAY");
    }
}
