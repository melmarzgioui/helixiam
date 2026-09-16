/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.wysiwys;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.4: a transaction-signing request is a single-use, expiry-bounded state machine —
 * PENDING until the device signs the canonical challenge, SIGNED once verified, then consumed once.
 */
class SignedTransactionTest {

    private SignedTransaction tx(final long createdAt, final long expiry) {
        return new SignedTransaction("tx-1", "user-7", "payment", "canonical", "nonce-1", createdAt, expiry);
    }

    @Test
    void startsPending() {
        assertThat(tx(0, 1_000).status()).isEqualTo(SignedTransaction.Status.PENDING);
    }

    @Test
    void signSucceedsBeforeExpiry() {
        final SignedTransaction t = tx(0, 1_000);
        assertThat(t.sign(999)).isTrue();
        assertThat(t.status()).isEqualTo(SignedTransaction.Status.SIGNED);
    }

    @Test
    void signFailsAndExpiresAtExpiry() {
        final SignedTransaction t = tx(0, 1_000);
        assertThat(t.sign(1_000)).isFalse();
        assertThat(t.status()).isEqualTo(SignedTransaction.Status.EXPIRED);
    }

    @Test
    void consumeReturnsUserOnceThenSingleUse() {
        final SignedTransaction t = tx(0, 1_000);
        t.sign(10);
        assertThat(t.consume()).isEqualTo("user-7");
        assertThat(t.status()).isEqualTo(SignedTransaction.Status.CONSUMED);
        assertThat(t.consume()).isNull();
    }

    @Test
    void consumeBeforeSignYieldsNothing() {
        assertThat(tx(0, 1_000).consume()).isNull();
    }
}
