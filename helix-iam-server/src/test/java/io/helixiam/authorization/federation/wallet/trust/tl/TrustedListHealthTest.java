/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListHealth.Status;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** The fail-safe rule: last good anchors until NextUpdate + grace, then nothing. */
class TrustedListHealthTest {

    static final Instant NEXT = Instant.parse("2026-11-01T00:00:00Z");
    static final Duration GRACE = Duration.ofHours(24);

    static Status at(final Instant now, final boolean failed) {
        return TrustedListHealth.evaluate(true, NEXT, GRACE, failed, true, now);
    }

    @Test
    void beforeNextUpdate_okOrFailing_bothUsable() {
        assertThat(at(NEXT.minusSeconds(1), false)).isEqualTo(Status.OK);
        assertThat(at(NEXT.minusSeconds(1), true)).isEqualTo(Status.FAILING);
        assertThat(at(NEXT, true).anchorsUsable()).isTrue();
    }

    @Test
    void pastNextUpdate_withinGrace_isStaleAndStillUsable() {
        assertThat(at(NEXT.plusSeconds(1), true)).isEqualTo(Status.STALE);
        assertThat(at(NEXT.plus(GRACE), true)).isEqualTo(Status.STALE);
        assertThat(Status.STALE.anchorsUsable()).isTrue();
    }

    @Test
    void pastGrace_isExpiredAndFailsClosed() {
        assertThat(at(NEXT.plus(GRACE).plusSeconds(1), true)).isEqualTo(Status.EXPIRED);
        assertThat(Status.EXPIRED.anchorsUsable()).isFalse();
    }

    @Test
    void zeroGrace_expiresRightAfterNextUpdate() {
        assertThat(TrustedListHealth.evaluate(true, NEXT, Duration.ZERO, true, true, NEXT.plusSeconds(1)))
                .isEqualTo(Status.EXPIRED);
    }

    @Test
    void neverLoaded_disabled_haveNoAnchors() {
        assertThat(TrustedListHealth.evaluate(true, null, GRACE, false, false, NEXT)).isEqualTo(Status.NEVER);
        assertThat(TrustedListHealth.evaluate(true, null, GRACE, true, true, NEXT)).isEqualTo(Status.ERROR);
        assertThat(TrustedListHealth.evaluate(false, NEXT, GRACE, false, true, NEXT.minusSeconds(5)))
                .isEqualTo(Status.DISABLED);
        assertThat(Status.NEVER.anchorsUsable() || Status.ERROR.anchorsUsable() || Status.DISABLED.anchorsUsable())
                .isFalse();
    }
}
