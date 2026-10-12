/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import java.time.Instant;

/** The checks both stores apply to a transaction passed to {@link WalletTransactionStore#create}. */
final class WalletTransactionValidation {

    private WalletTransactionValidation() {
    }

    static void requireNew(final WalletTransaction tx, final Instant now) {
        if (tx == null) {
            throw new IllegalArgumentException("A wallet transaction is required");
        }
        if (tx.status() != WalletTransaction.Status.CREATED) {
            throw new IllegalArgumentException("A new wallet transaction must be CREATED");
        }
        if (blank(tx.transactionId()) || blank(tx.sameDeviceRequestId()) || blank(tx.crossDeviceRequestId())
                || blank(tx.responseId()) || blank(tx.realmId())) {
            throw new IllegalArgumentException("A wallet transaction needs its id, both request ids, a response id "
                    + "and a realm");
        }
        if (tx.sameDeviceRequestId().equals(tx.crossDeviceRequestId())) {
            throw new IllegalArgumentException("The two request ids of a wallet transaction must differ");
        }
        if (tx.responseCode() != null || tx.verifiedIdentityJson() != null || tx.failureCode() != null) {
            throw new IllegalArgumentException("A new wallet transaction has no outcome yet");
        }
        if (tx.expiresAt() == null || tx.isExpiredAt(now)) {
            throw new IllegalArgumentException("A new wallet transaction must expire in the future");
        }
    }

    private static boolean blank(final String value) {
        return value == null || value.isBlank();
    }
}
