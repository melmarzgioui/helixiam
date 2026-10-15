/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Status;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
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
 *   <li><b>Bounded in time:</b> an expired transaction reads as absent and is removed on access; a background sweep
 *       (every {@value #DEFAULT_SWEEP_SECONDS} s by default) removes the ones nobody touches again, so an abandoned
 *       login's private key and identity do not stay in the heap.</li>
 *   <li><b>Bounded in size:</b> a slot is reserved atomically before the insert, so concurrent creates never exceed
 *       {@code maxEntries} (default {@value #DEFAULT_MAX_ENTRIES}). At the cap, {@code create} sweeps expired entries
 *       (at most once a second) and otherwise refuses rather than evicting a live transaction, so a burst of starts
 *       cannot cancel other users' logins.</li>
 *   <li><b>Not encrypted:</b> objects stay in process memory next to the key that would encrypt them, so encryption at
 *       rest would add nothing here.</li>
 * </ul>
 */
public class InMemoryWalletTransactionStore implements WalletTransactionStore, AutoCloseable {

    private static final Logger LOG = LogManager.getLogger(InMemoryWalletTransactionStore.class);

    public static final int DEFAULT_MAX_ENTRIES = 10_000;
    public static final int DEFAULT_SWEEP_SECONDS = 60;
    private static final long MIN_MILLIS_BETWEEN_CAP_SWEEPS = 1_000;

    /** A transaction plus the hashes of its bearer secrets. */
    private record Entry(WalletTransaction tx, String sameDeviceHash, String crossDeviceHash, String responseHash,
                         String codeHash) {

        Entry with(final WalletTransaction next) {
            return new Entry(next, sameDeviceHash, crossDeviceHash, responseHash, codeHash);
        }

        Entry with(final WalletTransaction next, final String newCodeHash) {
            return new Entry(next, sameDeviceHash, crossDeviceHash, responseHash, newCodeHash);
        }
    }

    private final ConcurrentMap<String, Entry> transactions = new ConcurrentHashMap<>();
    /** SHA-256 of a request id, response id or response code → transaction id. */
    private final ConcurrentMap<String, String> index = new ConcurrentHashMap<>();
    /** Reserved slots: incremented before an insert, decremented on removal or a failed insert. */
    private final AtomicInteger count = new AtomicInteger();
    private final AtomicLong lastCapSweepMillis = new AtomicLong(Long.MIN_VALUE);
    private final Clock clock;
    private final int maxEntries;
    private final ScheduledExecutorService sweeper;

    /** Production default: system clock, {@value #DEFAULT_MAX_ENTRIES} entries, a sweep every minute. */
    public InMemoryWalletTransactionStore() {
        this(Clock.systemUTC(), DEFAULT_MAX_ENTRIES, Duration.ofSeconds(DEFAULT_SWEEP_SECONDS));
    }

    /** Without a background sweep (tests call {@link #evictExpired()} themselves). */
    public InMemoryWalletTransactionStore(final Clock clock, final int maxEntries) {
        this(clock, maxEntries, null);
    }

    /**
     * @param sweepInterval fixed delay between background sweeps of expired entries; {@code null} for none. Stop it
     *                      with {@link #close()} (Spring does so for the bean).
     */
    public InMemoryWalletTransactionStore(final Clock clock, final int maxEntries, final Duration sweepInterval) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.clock = clock;
        this.maxEntries = maxEntries;
        if (sweepInterval == null) {
            this.sweeper = null;
        } else {
            this.sweeper = Executors.newSingleThreadScheduledExecutor(runnable -> {
                final Thread thread = new Thread(runnable, "wallet-transaction-sweep");
                thread.setDaemon(true);
                return thread;
            });
            final long millis = sweepInterval.toMillis();
            this.sweeper.scheduleWithFixedDelay(this::sweep, millis, millis, TimeUnit.MILLISECONDS);
        }
    }

    @Override
    public void close() {
        if (sweeper != null) {
            sweeper.shutdownNow();
        }
    }

    @Override
    public void create(final WalletTransaction tx) {
        final Instant now = clock.instant();
        WalletTransactionValidation.requireNew(tx, now);
        if (!reserveSlot()) {
            if (mayCapSweep(now)) {
                evictExpired();
            }
            if (!reserveSlot()) {
                throw new WalletTransactionCapacityException("Too many wallet logins in progress (" + maxEntries
                        + "); try again later");
            }
        }
        final Entry entry = new Entry(tx, SecretHash.of(tx.sameDeviceRequestId()),
                SecretHash.of(tx.crossDeviceRequestId()), SecretHash.of(tx.responseId()), null);
        if (transactions.putIfAbsent(tx.transactionId(), entry) != null) {
            count.decrementAndGet();
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
            final Flow flow = hash.equals(entry.sameDeviceHash()) ? Flow.SAME_DEVICE
                    : hash.equals(entry.crossDeviceHash()) ? Flow.CROSS_DEVICE : null;
            if (flow == null) {
                return null;
            }
            if (entry.tx().status() == Status.CREATED) {
                return entry.with(entry.tx().claimed(flow));
            }
            // A re-fetch (conformance ruling D2): the same request id, before the response arrived, changes nothing.
            return entry.tx().status() == Status.REQUEST_FETCHED && entry.tx().flow() == flow ? entry : null;
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
    public Optional<WalletTransaction> claimDcApiResponse(final String transactionId) {
        return transition(transactionId, entry -> entry.tx().status() == Status.CREATED
                ? entry.with(entry.tx().dcApiResponseReceived()) : null).map(Entry::tx);
    }

    @Override
    public boolean complete(final String transactionId, final String responseCode, final String verifiedIdentityJson) {
        final String codeHash = responseCode == null ? null : SecretHash.of(responseCode);
        final Optional<Entry> done = transition(transactionId, entry -> {
            final WalletTransaction tx = entry.tx();
            // Same-device: the direct_post handler hands the wallet the code. Cross-device and DC API: no code here;
            // the bound browser gets one from issueResponseCode.
            final boolean codeFitsFlow = tx.flow() == Flow.SAME_DEVICE ? codeHash != null : codeHash == null;
            return tx.status() == Status.RESPONSE_RECEIVED && codeFitsFlow
                    ? entry.with(tx.verified(verifiedIdentityJson), codeHash) : null;
        });
        if (done.isPresent() && codeHash != null) {
            index.put(codeHash, transactionId);
        }
        return done.isPresent();
    }

    @Override
    public Optional<String> issueResponseCode(final String transactionId, final String browserBindingHash) {
        final String code = SecretHash.newSecret();
        final String codeHash = SecretHash.of(code);
        final Optional<Entry> issued = transition(transactionId, entry -> {
            final WalletTransaction tx = entry.tx();
            final boolean bindingMatches = SecretHash.matches(browserBindingHash, tx.browserBindingHash());
            return tx.status() == Status.VERIFIED && (tx.flow() == Flow.CROSS_DEVICE || tx.flow() == Flow.DC_API)
                    && entry.codeHash() == null
                    && bindingMatches ? entry.with(tx, codeHash) : null;
        });
        if (issued.isEmpty()) {
            return Optional.empty();
        }
        index.put(codeHash, transactionId);
        return Optional.of(code);
    }

    @Override
    public boolean discard(final String transactionId) {
        if (transactionId == null) {
            return false;
        }
        while (true) {
            final Entry entry = transactions.get(transactionId);
            if (entry == null || !(entry.tx().status() == Status.CREATED
                    || entry.tx().status() == Status.REQUEST_FETCHED
                    || entry.tx().status() == Status.RESPONSE_RECEIVED)) {
                return false;
            }
            // Removes only the entry just checked; a transition in between makes this fail, and the loop looks again.
            if (transactions.remove(transactionId, entry)) {
                count.decrementAndGet();
                index.remove(entry.sameDeviceHash(), transactionId);
                index.remove(entry.crossDeviceHash(), transactionId);
                index.remove(entry.responseHash(), transactionId);
                if (entry.codeHash() != null) {
                    index.remove(entry.codeHash(), transactionId);
                }
                return true;
            }
        }
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

    private boolean reserveSlot() {
        while (true) {
            final int current = count.get();
            if (current >= maxEntries) {
                return false;
            }
            if (count.compareAndSet(current, current + 1)) {
                return true;
            }
        }
    }

    /** At most one sweep a second from {@code create}, so a full store of live entries is not scanned per call. */
    private boolean mayCapSweep(final Instant now) {
        final long nowMillis = now.toEpochMilli();
        final long last = lastCapSweepMillis.get();
        return (last == Long.MIN_VALUE || nowMillis - last >= MIN_MILLIS_BETWEEN_CAP_SWEEPS)
                && lastCapSweepMillis.compareAndSet(last, nowMillis);
    }

    private void sweep() {
        try {
            evictExpired();
        } catch (final RuntimeException e) {
            LOG.warn("Wallet transaction sweep failed: {}", e.getClass().getSimpleName());
        }
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
            count.decrementAndGet();
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
