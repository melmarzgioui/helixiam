/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.transaction;

import org.junit.jupiter.api.Test;

import java.time.Clock;

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
}
