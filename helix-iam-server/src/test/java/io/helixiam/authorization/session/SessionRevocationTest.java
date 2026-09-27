/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.session;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** B1: which browser sessions survive "sign out everywhere else" and account deletion. */
class SessionRevocationTest {

    private static final long REVOKED_AT = 1_800_000_000_500L; // epoch millis

    @Test
    void aUserWhoNeverSignedOutOthers_keepsEverySession() {
        assertThat(SessionRevocation.valid(SessionRevocation.State.of(null), 1L, 1L, null)).isTrue();
    }

    @Test
    void aDeletedUser_losesEverySession() {
        assertThat(SessionRevocation.valid(SessionRevocation.State.GONE, 1_900_000_000_000L, 1L, null)).isFalse();
    }

    @Test
    void aSignInBeforeTheRevocation_ends_andOneAfterItStays() {
        final SessionRevocation.State s = SessionRevocation.State.of(REVOKED_AT);
        assertThat(SessionRevocation.valid(s, REVOKED_AT - 1, 1L, null)).isFalse();
        assertThat(SessionRevocation.valid(s, REVOKED_AT, 1L, null)).isFalse();
        assertThat(SessionRevocation.valid(s, REVOKED_AT + 1, 1L, null)).isTrue();
    }

    @Test
    void theSessionThatAsked_isKept() {
        final SessionRevocation.State s = SessionRevocation.State.of(REVOKED_AT);
        assertThat(SessionRevocation.valid(s, 1_700_000_000_000L, 1L, REVOKED_AT)).isTrue();
        assertThat(SessionRevocation.valid(s, 1_700_000_000_000L, 1L, REVOKED_AT - 1)).as("kept by an older revocation").isFalse();
    }

    @Test
    void aSessionThatHasNotFinishedSigningIn_isJudgedByWhenItStarted() {
        final SessionRevocation.State s = SessionRevocation.State.of(REVOKED_AT);
        assertThat(SessionRevocation.valid(s, null, REVOKED_AT - 1, null)).isFalse();
        assertThat(SessionRevocation.valid(s, null, REVOKED_AT + 1, null)).isTrue();
    }
}
