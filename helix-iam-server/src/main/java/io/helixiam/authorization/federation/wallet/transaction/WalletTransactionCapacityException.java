/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

/**
 * The store cannot take another wallet login right now (the in-memory store is at its cap). A temporary condition:
 * the wallet page shows a friendly "try again later" with HTTP 503, never an error page.
 */
public class WalletTransactionCapacityException extends IllegalStateException {

    public WalletTransactionCapacityException(final String message) {
        super(message);
    }
}
