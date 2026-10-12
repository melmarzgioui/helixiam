/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;

import java.util.Locale;

/**
 * Final review m2: the plain-language kind of failure the wallet page shows ({@code wallet.failed.<key>}) and the
 * status endpoint names ({@code "reason"}). Coarse on purpose: the browser learns whether the user declined, the
 * shared credential was not accepted, the sign-in ran out of time, or something went wrong — never which check failed
 * (that is in the audit log and the server log only).
 */
enum WalletFailureClass {
    /** The user declined in the wallet. */
    DECLINED,
    /** A credential was shared, and refused: untrusted, revoked, expired, not bound to the wallet, not the PID asked for. */
    NOT_ACCEPTED,
    /** The sign-in ran out of time. */
    EXPIRED,
    /** Anything else: a malformed or replayed response, a status service that did not answer, a mixed-up browser. */
    TECHNICAL;

    /** The class of {@code code}; {@code null} (no recorded code) is technical. */
    static WalletFailureClass of(final WalletErrorCode code) {
        if (code == null) {
            return TECHNICAL;
        }
        return switch (code) {
            case WALLET_ACCESS_DENIED -> DECLINED;
            case TRANSACTION_EXPIRED -> EXPIRED;
            case ISSUER_SIGNATURE_INVALID, ISSUER_UNTRUSTED, CREDENTIAL_EXPIRED, CREDENTIAL_NOT_YET_VALID,
                 CREDENTIAL_REVOKED, CREDENTIAL_SUSPENDED, STATUS_REQUIRED, HOLDER_BINDING_MISSING,
                 HOLDER_BINDING_INVALID, NONCE_MISMATCH, AUDIENCE_MISMATCH, DISCLOSURE_INVALID, DIGEST_MISMATCH,
                 DCQL_NOT_SATISFIED, VCT_NOT_ACCEPTED, DOCTYPE_NOT_ACCEPTED, ALGORITHM_NOT_ALLOWED, UNSUPPORTED_FORMAT,
                 SUBJECT_UNAVAILABLE -> NOT_ACCEPTED;
            case INVALID_RESPONSE, STATUS_UNAVAILABLE, LIMIT_EXCEEDED, DECRYPTION_FAILED, STATE_MISMATCH, REPLAY,
                 WALLET_ERROR, BROWSER_MISMATCH -> TECHNICAL;
        };
    }

    /** The message-key suffix and the status endpoint's {@code reason}, e.g. {@code not_accepted}. */
    String key() {
        return name().toLowerCase(Locale.ROOT);
    }
}
