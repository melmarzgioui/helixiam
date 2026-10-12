/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The shared store contract against {@link InMemoryWalletTransactionStore}, plus its size cap and eviction. */
class InMemoryWalletTransactionStoreTest extends AbstractWalletTransactionStoreTest {

    private static final int CAP = 3;

    @Override
    WalletTransactionStore newStore(final Clock clock) {
        return new InMemoryWalletTransactionStore(clock, 1000);
    }

    @Test
    void whenFullOfLiveTransactions_createIsRefused_withoutEvictingAny() {
        final InMemoryWalletTransactionStore small = new InMemoryWalletTransactionStore(clock, CAP);
        store = small;
        final WalletTransaction first = created();
        created();
        created();

        assertThatThrownBy(() -> store.create(newTransaction())).isInstanceOf(IllegalStateException.class);
        assertThat(store.byTransactionId(first.transactionId())).isPresent();
        assertThat(small.size()).isEqualTo(CAP);
    }

    @Test
    void whenFull_expiredTransactionsAreEvicted_andCreateSucceeds() {
        final InMemoryWalletTransactionStore small = new InMemoryWalletTransactionStore(clock, CAP);
        store = small;
        created();
        created();
        created();
        clock.advance(TTL);

        final WalletTransaction fresh = created();

        assertThat(small.size()).isEqualTo(1);
        assertThat(store.claimRequest(fresh.crossDeviceRequestId())).isPresent();
    }

    @Test
    void createsRacingForTheLastSlots_neverOvershootTheCap() throws Exception {
        final InMemoryWalletTransactionStore small = new InMemoryWalletTransactionStore(clock, CAP);
        store = small;
        final List<WalletTransaction> candidates = new java.util.ArrayList<>();
        for (int i = 0; i < 20; i++) {
            candidates.add(newTransaction());
        }

        final List<Boolean> created = race(20, i -> {
            try {
                small.create(candidates.get(i));
                return true;
            } catch (final IllegalStateException full) {
                return false;
            }
        });

        assertThat(created.stream().filter(Boolean::booleanValue).count()).isEqualTo(CAP);
        assertThat(small.size()).isEqualTo(CAP);
    }

    @Test
    void theScheduledSweep_dropsExpiredTransactions_withoutAnyAccess() throws Exception {
        try (InMemoryWalletTransactionStore swept =
                     new InMemoryWalletTransactionStore(clock, 100, Duration.ofMillis(20))) {
            store = swept;
            created();
            final WalletTransaction live = newTransaction();
            clock.advance(TTL.minusSeconds(1));
            swept.create(copy(live, live.sameDeviceRequestId(), live.crossDeviceRequestId(), live.responseId(),
                    clock.instant(), clock.instant().plus(TTL)));
            clock.advance(Duration.ofSeconds(1));

            final long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
            while (swept.size() > 1 && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }

            assertThat(swept.size()).isEqualTo(1);
            assertThat(swept.indexSize()).isEqualTo(3);
            assertThat(store.byTransactionId(live.transactionId())).isPresent();
        }
    }

    @Test
    void evictExpired_removesExpiredTransactionsAndTheirIndexes() {
        final InMemoryWalletTransactionStore inMemory = (InMemoryWalletTransactionStore) store;
        final WalletTransaction tx = created();
        clock.advance(TTL);

        inMemory.evictExpired();

        assertThat(inMemory.size()).isZero();
        assertThat(inMemory.indexSize()).isZero();
        assertThat(store.claimRequest(tx.crossDeviceRequestId())).isEmpty();
    }

    @Test
    void indexesHoldOnlyHashes_neverTheRawBearerSecrets() {
        final InMemoryWalletTransactionStore inMemory = (InMemoryWalletTransactionStore) store;
        final Verified v = verified();

        assertThat(inMemory.indexKeys()).hasSize(4)
                .doesNotContain(v.tx().sameDeviceRequestId(), v.tx().crossDeviceRequestId(), v.tx().responseId(),
                        v.code())
                .contains(SecretHash.of(v.code()), SecretHash.of(v.tx().responseId()));
        assertThat(store.byTransactionId(v.tx().transactionId()).orElseThrow().responseCode()).isNull();
    }

    /** Task 18 fix round 1: a discarded transaction frees its slot under the cap. */
    @Test
    void discard_freesTheSlot() {
        final InMemoryWalletTransactionStore capped = new InMemoryWalletTransactionStore(clock, 1, null);
        final WalletTransaction first = newTransaction();
        capped.create(first);
        assertThatThrownBy(() -> capped.create(newTransaction()))
                .isInstanceOf(WalletTransactionCapacityException.class);

        assertThat(capped.discard(first.transactionId())).isTrue();
        capped.create(newTransaction());
    }
}
