/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The wallet error codes are an audit/UI contract: each has a stable, lower-case {@code wallet.*} reason, and the
 * exception carries the code without leaking anything but the safe detail.
 */
class WalletErrorCodeTest {

    @Test
    void reasonIsStableLowerCaseWalletPrefixedName() {
        assertThat(WalletErrorCode.CREDENTIAL_REVOKED.reason()).isEqualTo("wallet.credential_revoked");
        assertThat(WalletErrorCode.LIMIT_EXCEEDED.reason()).isEqualTo("wallet.limit_exceeded");
        assertThat(WalletErrorCode.BROWSER_MISMATCH.reason()).isEqualTo("wallet.browser_mismatch");
    }

    @Test
    void everyReasonIsUniqueAndWellFormed() {
        Set<String> reasons = Arrays.stream(WalletErrorCode.values()).map(WalletErrorCode::reason)
                .collect(Collectors.toSet());
        assertThat(reasons).hasSize(WalletErrorCode.values().length);
        assertThat(reasons).allMatch(r -> r.matches("wallet\\.[a-z_]+"));
    }

    @Test
    void theContractedCodesExist() {
        assertThat(Arrays.stream(WalletErrorCode.values()).map(Enum::name)).containsExactly(
                "INVALID_RESPONSE", "UNSUPPORTED_FORMAT", "ISSUER_SIGNATURE_INVALID", "ISSUER_UNTRUSTED",
                "CREDENTIAL_EXPIRED", "CREDENTIAL_NOT_YET_VALID", "CREDENTIAL_REVOKED", "CREDENTIAL_SUSPENDED",
                "STATUS_UNAVAILABLE", "STATUS_REQUIRED", "HOLDER_BINDING_MISSING", "HOLDER_BINDING_INVALID",
                "NONCE_MISMATCH", "AUDIENCE_MISMATCH", "DISCLOSURE_INVALID", "DIGEST_MISMATCH",
                "DCQL_NOT_SATISFIED", "VCT_NOT_ACCEPTED", "DOCTYPE_NOT_ACCEPTED", "ALGORITHM_NOT_ALLOWED",
                "LIMIT_EXCEEDED", "DECRYPTION_FAILED", "STATE_MISMATCH", "TRANSACTION_EXPIRED", "REPLAY",
                "WALLET_ACCESS_DENIED", "WALLET_ERROR", "SUBJECT_UNAVAILABLE", "BROWSER_MISMATCH", "BINDING_MISMATCH");
    }

    @Test
    void exceptionCarriesCodeAndSafeDetail() {
        WalletVerificationException e =
                new WalletVerificationException(WalletErrorCode.NONCE_MISMATCH, "nonce does not match");
        assertThat(e.code()).isEqualTo(WalletErrorCode.NONCE_MISMATCH);
        assertThat(e.getMessage()).isEqualTo("nonce does not match");
        assertThat(e).isInstanceOf(RuntimeException.class);
    }
}
