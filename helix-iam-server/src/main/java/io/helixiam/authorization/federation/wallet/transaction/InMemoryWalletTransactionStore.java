/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Status;

import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

/**
 * Single-node {@link WalletTransactionStore}, for tests, development and one-replica deployments (a wallet's request
 * and response must reach the replica that holds the transaction). Mirrors {@code InMemorySamlAssertionReplayCache}.
 *
 * <ul>
 *   <li><b>Atomicity:</b> every transition is one {@link ConcurrentMap#computeIfPresent} on the transaction, so two
 *       concurrent claims of the same transaction serialise and only the first sees the expected state.</li>
 *   <li><b>Bearer secrets:</b> the request, response and code indexes are keyed by SHA-256, and the response code is
 *       kept only as its hash, exactly like the Redis store.</li>
 *   <li><b>Bounded:</b> expired transactions read as absent and are removed on access; {@code create} also sweeps
 *       every expired one once the store holds half its cap. At the cap ({@code maxEntries}, default
 *       {@value #DEFAULT_MAX_ENTRIES}) a new transaction is refused rather than evicting a live one, so a burst of
 *       starts cannot cancel other users' logins.</li>
 *   <li><b>Not encrypted:</b> objects stay in process memory next to the key that would encrypt them, so encryption at
 *       rest would add nothing here.</li>
 * </ul>
 */
public class InMemoryWalletTransactionStore implements WalletTransactionStore {

    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    /** A transaction plus the hashes of its bearer secrets. */
    private record Entry(WalletTransaction tx, String sameDeviceHash, String crossDeviceHash, String responseHash,
                         String codeHash) {

        Entry with(final WalletTransaction next) {
            return new Entry(next, sameDeviceHash, crossDeviceHash, responseHash, codeHash);
        }
    }

    private final ConcurrentMap<String, Entry> transactions = new ConcurrentHashMap<>();
    /** SHA-256 of a request id, response id or response code → transaction id. */
    private final ConcurrentMap<String, String> index = new ConcurrentHashMap<>();
    private final Clock clock;
    private final int maxEntries;

    public InMemoryWalletTransactionStore() {
        this(Clock.systemUTC(), DEFAULT_MAX_ENTRIES);
    }

    public InMemoryWalletTransactionStore(final Clock clock, final int maxEntries) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.clock = clock;
        this.maxEntries = maxEntries;
    }

    @Override
    public void create(final WalletTransaction tx) {
        WalletTransactionValidation.requireNew(tx, clock.instant());
        if (transactions.size() >= maxEntries / 2) {
            evictExpired();
        }
        if (transactions.size() >= maxEntries) {
            throw new IllegalStateException("Too many wallet logins in progress (" + maxEntries + "); try again later");
        }
        final Entry entry = new Entry(tx, SecretHash.of(tx.sameDeviceRequestId()),
                SecretHash.of(tx.crossDeviceRequestId()), SecretHash.of(tx.responseId()), null);
        if (transactions.putIfAbsent(tx.transactionId(), entry) != null) {
            throw new IllegalArgumentException("A wallet transaction with this id already exists");
        }
        index.put(entry.sameDeviceHash(), tx.transactionId());
        index.put(entry.crossDeviceHash(), tx.transactionId());
        index.put(entry.responseHash(), tx.transactionId());
    }

    @Override
    public Optional<WalletTransaction> byTransactionId(final String id) {
        if (id == null) {
            return Optional.empty();
        }
        final Entry entry = transactions.get(id);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.tx().isExpiredAt(clock.instant())) {
            remove(id);
            return Optional.empty();
        }
        return Optional.of(entry.tx());
    }

    @Override
    public Optional<WalletTransaction> claimRequest(final String requestId) {
        if (requestId == null) {
            return Optional.empty();
        }
        final String hash = SecretHash.of(requestId);
        return transition(index.get(hash), entry -> {
            if (entry.tx().status() != Status.CREATED) {
                return null;
            }
            final Flow flow = hash.equals(entry.sameDeviceHash()) ? Flow.SAME_DEVICE
                    : hash.equals(entry.crossDeviceHash()) ? Flow.CROSS_DEVICE : null;
            return flow == null ? null : entry.with(entry.tx().claimed(flow));
        }).map(Entry::tx);
    }

    @Override
    public Optional<WalletTransaction> claimResponse(final String responseId) {
        if (responseId == null) {
            return Optional.empty();
        }
        final String hash = SecretHash.of(responseId);
        return transition(index.get(hash), entry -> entry.tx().status() == Status.REQUEST_FETCHED
                && hash.equals(entry.responseHash())
                ? entry.with(entry.tx().withStatus(Status.RESPONSE_RECEIVED)) : null).map(Entry::tx);
    }

    @Override
    public boolean complete(final String transactionId, final String responseCode, final String verifiedIdentityJson) {
        if (responseCode == null) {
            return false;
        }
        final String codeHash = SecretHash.of(responseCode);
        final Optional<Entry> done = transition(transactionId, entry -> entry.tx().status() == Status.RESPONSE_RECEIVED
                ? new Entry(entry.tx().verified(verifiedIdentityJson), entry.sameDeviceHash(),
                entry.crossDeviceHash(), entry.responseHash(), codeHash) : null);
        done.ifPresent(entry -> index.put(codeHash, entry.tx().transactionId()));
        return done.isPresent();
    }

    @Override
    public boolean fail(final String transactionId, final WalletErrorCode code) {
        return transition(transactionId, entry -> entry.tx().status() == Status.REQUEST_FETCHED
                || entry.tx().status() == Status.RESPONSE_RECEIVED
                ? entry.with(entry.tx().failed(code)) : null).isPresent();
    }

    @Override
    public Optional<WalletTransaction> redeem(final String responseCode, final String helixState,
                                              final String browserBindingHash) {
        if (responseCode == null) {
            return Optional.empty();
        }
        final String codeHash = SecretHash.of(responseCode);
        final AtomicReference<WalletTransaction> redeemed = new AtomicReference<>();
        transition(index.get(codeHash), entry -> {
            final WalletTransaction tx = entry.tx();
            // Evaluate all three so the time taken does not say which one was wrong.
            final boolean codeMatches = SecretHash.matches(codeHash, entry.codeHash());
            final boolean stateMatches = SecretHash.matches(helixState, tx.helixState());
            final boolean bindingMatches = SecretHash.matches(browserBindingHash, tx.browserBindingHash());
            if (tx.status() != Status.VERIFIED || !(codeMatches & stateMatches & bindingMatches)) {
                return null;
            }
            redeemed.set(tx.withStatus(Status.REDEEMED));
            return entry.with(tx.redeemedWithoutIdentity());
        });
        return Optional.ofNullable(redeemed.get());
    }

    /**
     * Applies {@code step} atomically to a live transaction. {@code step} returns the new entry, or {@code null} when
     * the transition is not allowed (nothing changes). Returns the new entry when it was applied.
     */
    private Optional<Entry> transition(final String transactionId, final UnaryOperator<Entry> step) {
        if (transactionId == null) {
            return Optional.empty();
        }
        final Instant now = clock.instant();
        final AtomicReference<Entry> applied = new AtomicReference<>();
        final AtomicBoolean expired = new AtomicBoolean();
        transactions.computeIfPresent(transactionId, (id, entry) -> {
            if (entry.tx().isExpiredAt(now)) {
                expired.set(true);
                return entry;
            }
            final Entry next = step.apply(entry);
            if (next == null) {
                return entry;
            }
            applied.set(next);
            return next;
        });
        if (expired.get()) {
            remove(transactionId);
        }
        return Optional.ofNullable(applied.get());
    }

    /** Removes every expired transaction and its index entries. */
    void evictExpired() {
        final Instant now = clock.instant();
        transactions.forEach((id, entry) -> {
            if (entry.tx().isExpiredAt(now)) {
                remove(id);
            }
        });
    }

    private void remove(final String transactionId) {
        final Entry removed = transactions.remove(transactionId);
        if (removed != null) {
            index.remove(removed.sameDeviceHash(), transactionId);
            index.remove(removed.crossDeviceHash(), transactionId);
            index.remove(removed.responseHash(), transactionId);
            if (removed.codeHash() != null) {
                index.remove(removed.codeHash(), transactionId);
            }
        }
    }

    int size() {
        return transactions.size();
    }

    int indexSize() {
        return index.size();
    }

    Set<String> indexKeys() {
        return Set.copyOf(index.keySet());
    }
}
