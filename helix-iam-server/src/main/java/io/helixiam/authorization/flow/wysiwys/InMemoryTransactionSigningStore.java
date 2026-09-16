/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.wysiwys;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Helix IAM E4.4: default in-process {@link TransactionSigningStore} (single-instance / dev). A
 * Redis-backed store replaces it for horizontal scale (@ConditionalOnMissingBean in FlowConfig).
 * Requests are short-lived (signing TTL) and removed on consume, so growth is bounded.
 */
public class InMemoryTransactionSigningStore implements TransactionSigningStore {

    private final ConcurrentMap<String, SignedTransaction> transactions = new ConcurrentHashMap<>();

    @Override
    public void save(final SignedTransaction transaction) {
        transactions.put(transaction.id(), transaction);
    }

    @Override
    public Optional<SignedTransaction> find(final String id) {
        return Optional.ofNullable(transactions.get(id));
    }

    @Override
    public void remove(final String id) {
        transactions.remove(id);
    }
}
