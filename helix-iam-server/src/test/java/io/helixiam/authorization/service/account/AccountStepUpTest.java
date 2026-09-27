/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.security.session.AuthTimeStamper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/** B1: sensitive account actions need a sign-in (or re-authentication) no older than the step-up window. */
class AccountStepUpTest {

    private static final long NOW = 1_800_000_000L;

    private final AccountStepUp stepUp = new AccountStepUp(300, () -> NOW);

    @Test
    void aSignInWithinTheWindow_isFresh() {
        assertThat(stepUp.fresh(signedInSecondsAgo(0))).isTrue();
        assertThat(stepUp.fresh(signedInSecondsAgo(300))).isTrue();
    }

    @Test
    void anOlderSignIn_aSessionWithoutAuthTime_orNoSession_isNotFresh() {
        assertThat(stepUp.fresh(signedInSecondsAgo(301))).isFalse();
        final MockHttpServletRequest noAuthTime = new MockHttpServletRequest();
        noAuthTime.getSession(true);
        assertThat(stepUp.fresh(noAuthTime)).isFalse();
        assertThat(stepUp.fresh(new MockHttpServletRequest())).isFalse();
    }

    @Test
    void anAuthTimeInTheFuture_isNotTrusted() {
        assertThat(stepUp.fresh(signedInSecondsAgo(-120))).isFalse();
    }

    @Test
    void theWindow_isClampedToSaneBounds() {
        assertThat(new AccountStepUp(0, () -> NOW).maxAgeSeconds()).isEqualTo(30);
        assertThat(new AccountStepUp(999_999, () -> NOW).maxAgeSeconds()).isEqualTo(3600);
    }

    private static MockHttpServletRequest signedInSecondsAgo(final long seconds) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute(AuthTimeStamper.HELIX_AUTH_TIME, NOW - seconds);
        return request;
    }
}
