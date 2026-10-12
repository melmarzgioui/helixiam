/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import java.time.Duration;
import java.time.Instant;

/** The checks both stores apply to a transaction passed to {@link WalletTransactionStore#create}. */
final class WalletTransactionValidation {

    /** The configurable transaction TTL range (constraints: 300 s default, 60–900 s). */
    static final Duration MIN_LIFETIME = Duration.ofSeconds(60);
    static final Duration MAX_LIFETIME = Duration.ofSeconds(900);

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
        if (tx.sameDeviceRequestId().equals(tx.crossDeviceRequestId())
                || tx.responseId().equals(tx.sameDeviceRequestId())
                || tx.responseId().equals(tx.crossDeviceRequestId())) {
            throw new IllegalArgumentException("The request ids and the response id of a wallet transaction must all "
                    + "differ");
        }
        if (tx.responseCode() != null || tx.verifiedIdentityJson() != null || tx.failureCode() != null) {
            throw new IllegalArgumentException("A new wallet transaction has no outcome yet");
        }
        if (tx.createdAt() == null || tx.expiresAt() == null || tx.isExpiredAt(now)) {
            throw new IllegalArgumentException("A new wallet transaction needs a creation time and must expire in "
                    + "the future");
        }
        final Duration lifetime = Duration.between(tx.createdAt(), tx.expiresAt());
        if (lifetime.compareTo(MIN_LIFETIME) < 0 || lifetime.compareTo(MAX_LIFETIME) > 0) {
            throw new IllegalArgumentException("A wallet transaction must live between " + MIN_LIFETIME.toSeconds()
                    + " and " + MAX_LIFETIME.toSeconds() + " seconds");
        }
    }

    private static boolean blank(final String value) {
        return value == null || value.isBlank();
    }
}
