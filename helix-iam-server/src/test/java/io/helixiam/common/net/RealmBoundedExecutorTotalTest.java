/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** Besides the per-realm bound, one ceiling across all realms: many realms together cannot pile up unbounded work. */
class RealmBoundedExecutorTotalTest {

    @Test
    void manyRealmsTogetherStopAtTheGlobalCeilingAndTheRestIsDroppedWithoutBlocking() throws Exception {
        final RealmBoundedExecutor queue = new RealmBoundedExecutor("test", 1_000, 2_500);
        final CountDownLatch release = new CountDownLatch(1);
        final long start = System.nanoTime();
        int accepted = 0;
        for (int realm = 0; realm < 5; realm++) {
            for (int i = 0; i < 1_000; i++) {
                if (queue.submit("r" + realm, () -> {
                    try {
                        release.await();
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                })) {
                    accepted++;
                }
            }
        }
        assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(5_000);
        assertThat(accepted).isEqualTo(2_500);
        assertThat(queue.pendingTotal()).isEqualTo(2_500);
        assertThat(queue.droppedTotal()).isEqualTo(2_500);
        release.countDown();
        final long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (queue.pendingTotal() > 0 && System.nanoTime() < until) {
            Thread.sleep(10);
        }
        assertThat(queue.pendingTotal()).isZero();
        assertThat(queue.submit("r9", () -> { })).isTrue();
    }

    @Test
    void theDefaultCeilingIsTwentyThousandAndConfigurable() {
        final RealmBoundedExecutor queue = new RealmBoundedExecutor("test", 1_000);
        assertThat(queue.maxPendingTotal()).isEqualTo(RealmBoundedExecutor.DEFAULT_MAX_PENDING_TOTAL)
                .isEqualTo(20_000);
        queue.setMaxPendingTotal(5_000);
        assertThat(queue.maxPendingTotal()).isEqualTo(5_000);
    }
}
