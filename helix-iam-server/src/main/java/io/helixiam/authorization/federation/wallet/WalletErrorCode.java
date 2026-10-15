/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

/**
 * Why a wallet presentation (or the transaction around it) was refused. The names are an audit/UI contract: log and
 * show {@link #reason()}, never the raw presentation.
 */
public enum WalletErrorCode {
    INVALID_RESPONSE, UNSUPPORTED_FORMAT, ISSUER_SIGNATURE_INVALID, ISSUER_UNTRUSTED, CREDENTIAL_EXPIRED,
    CREDENTIAL_NOT_YET_VALID, CREDENTIAL_REVOKED, CREDENTIAL_SUSPENDED, STATUS_UNAVAILABLE, STATUS_REQUIRED,
    HOLDER_BINDING_MISSING, HOLDER_BINDING_INVALID, NONCE_MISMATCH, AUDIENCE_MISMATCH, DISCLOSURE_INVALID,
    DIGEST_MISMATCH, DCQL_NOT_SATISFIED, VCT_NOT_ACCEPTED, DOCTYPE_NOT_ACCEPTED, ALGORITHM_NOT_ALLOWED,
    LIMIT_EXCEEDED, DECRYPTION_FAILED, STATE_MISMATCH, TRANSACTION_EXPIRED, REPLAY, WALLET_ACCESS_DENIED,
    WALLET_ERROR, SUBJECT_UNAVAILABLE, BROWSER_MISMATCH,
    /** Verify-only mode: the presented wallet is not the signed-in user's (it is linked to another account). */
    BINDING_MISMATCH;

    /** Stable reason code for audit/UI, e.g. "wallet.credential_revoked". */
    public String reason() { return "wallet." + name().toLowerCase(java.util.Locale.ROOT); }
}
