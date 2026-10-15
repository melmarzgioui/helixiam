/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Final review m2: the browser is told, in plain language, which kind of failure ended a wallet login (declined, not
 * accepted, expired, technical), never the specific check. A revoked, expired or untrusted credential was shared and
 * then not accepted: it must not read as "your wallet did not share your identity".
 */
class WalletFailureClassTest {

    @Test
    void theUserDecliningInTheWallet_isDeclined() {
        assertThat(WalletFailureClass.of(WalletErrorCode.WALLET_ACCESS_DENIED)).isEqualTo(WalletFailureClass.DECLINED);
    }

    @ParameterizedTest
    @EnumSource(value = WalletErrorCode.class, names = {"CREDENTIAL_REVOKED", "CREDENTIAL_SUSPENDED", "ISSUER_UNTRUSTED",
            "ISSUER_SIGNATURE_INVALID", "CREDENTIAL_EXPIRED", "CREDENTIAL_NOT_YET_VALID", "STATUS_REQUIRED",
            "HOLDER_BINDING_MISSING", "HOLDER_BINDING_INVALID", "NONCE_MISMATCH", "AUDIENCE_MISMATCH",
            "DISCLOSURE_INVALID", "DIGEST_MISMATCH", "DCQL_NOT_SATISFIED", "VCT_NOT_ACCEPTED", "DOCTYPE_NOT_ACCEPTED",
            "ALGORITHM_NOT_ALLOWED", "UNSUPPORTED_FORMAT", "SUBJECT_UNAVAILABLE", "BINDING_MISMATCH"})
    void aSharedCredentialThatIsRefused_isNotAccepted(final WalletErrorCode code) {
        assertThat(WalletFailureClass.of(code)).isEqualTo(WalletFailureClass.NOT_ACCEPTED);
    }

    @Test
    void aSignInThatRanOutOfTime_isExpired() {
        assertThat(WalletFailureClass.of(WalletErrorCode.TRANSACTION_EXPIRED)).isEqualTo(WalletFailureClass.EXPIRED);
    }

    @ParameterizedTest
    @EnumSource(value = WalletErrorCode.class, names = {"INVALID_RESPONSE", "STATUS_UNAVAILABLE", "LIMIT_EXCEEDED",
            "DECRYPTION_FAILED", "STATE_MISMATCH", "REPLAY", "WALLET_ERROR", "BROWSER_MISMATCH"})
    void anythingElse_isTechnical(final WalletErrorCode code) {
        assertThat(WalletFailureClass.of(code)).isEqualTo(WalletFailureClass.TECHNICAL);
    }

    @Test
    void noCode_isTechnical_andEveryClassHasAStableMessageKey() {
        assertThat(WalletFailureClass.of(null)).isEqualTo(WalletFailureClass.TECHNICAL);
        assertThat(WalletFailureClass.NOT_ACCEPTED.key()).isEqualTo("not_accepted");
        assertThat(WalletFailureClass.DECLINED.key()).isEqualTo("declined");
        assertThat(WalletFailureClass.EXPIRED.key()).isEqualTo("expired");
        assertThat(WalletFailureClass.TECHNICAL.key()).isEqualTo("technical");
    }
}
