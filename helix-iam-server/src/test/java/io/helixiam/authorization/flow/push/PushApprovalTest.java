/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.push;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.3: push approval with number matching. The browser shows one 2-digit number; the
 * phone shows several and the user must tap the matching one — defeating blind "approve" taps
 * (MFA fatigue). The approval is a single-use, TTL-bounded state machine: a wrong number is an
 * explicit DENY (a fraud/fatigue signal), the right one APPROVES, and consume is one-shot.
 */
class PushApprovalTest {

    private static final long TTL = 120_000L; // 2 minutes

    private PushApproval approval(final long createdAt) {
        return new PushApproval("push-1", "user-7", 42, "nonce-abc", createdAt, TTL);
    }

    @Test
    void startsPendingWithItsExpectedNumber() {
        final PushApproval a = approval(0);
        assertThat(a.status()).isEqualTo(PushApproval.Status.PENDING);
        assertThat(a.expectedNumber()).isEqualTo(42);
        assertThat(a.challenge()).isEqualTo("nonce-abc");
    }

    @Test
    void approveSucceedsForTheMatchingNumber() {
        final PushApproval a = approval(0);
        assertThat(a.approve(42, 1_000)).isTrue();
        assertThat(a.status()).isEqualTo(PushApproval.Status.APPROVED);
    }

    @Test
    void approveWithTheWrongNumberIsAnExplicitDeny() {
        final PushApproval a = approval(0);
        assertThat(a.approve(13, 1_000)).isFalse();
        assertThat(a.status()).isEqualTo(PushApproval.Status.DENIED);
    }

    @Test
    void approveAfterTtlExpires() {
        final PushApproval a = approval(0);
        assertThat(a.approve(42, TTL)).isFalse();
        assertThat(a.status()).isEqualTo(PushApproval.Status.EXPIRED);
    }

    @Test
    void denyMovesToDenied() {
        final PushApproval a = approval(0);
        a.deny();
        assertThat(a.status()).isEqualTo(PushApproval.Status.DENIED);
        assertThat(a.approve(42, 1_000)).isFalse(); // can't approve a denied request
    }

    @Test
    void consumeReturnsTheUserOnceThenIsSingleUse() {
        final PushApproval a = approval(0);
        a.approve(42, 1_000);
        assertThat(a.consume()).isEqualTo("user-7");
        assertThat(a.status()).isEqualTo(PushApproval.Status.CONSUMED);
        assertThat(a.consume()).isNull();
    }

    @Test
    void consumeBeforeApprovalYieldsNothing() {
        assertThat(approval(0).consume()).isNull();
    }
}
