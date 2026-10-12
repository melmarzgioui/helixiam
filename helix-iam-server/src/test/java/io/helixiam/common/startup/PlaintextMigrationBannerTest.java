/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.startup;

import org.junit.jupiter.api.Test;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** The plaintext-read migration mode is loud: an ERROR banner at startup, repeated every hour. */
class PlaintextMigrationBannerTest {

    @Test
    void whenMigrating_theBannerIsLoggedAtStartupAndEveryHour() {
        final ScheduledExecutorService scheduler = mock(ScheduledExecutorService.class);

        new PlaintextMigrationBanner(true, "2026-10-30", scheduler).start();

        verify(scheduler).scheduleAtFixedRate(any(Runnable.class), eq(0L), eq(1L), eq(TimeUnit.HOURS));
    }

    @Test
    void whenNotMigrating_nothingIsScheduled() {
        final ScheduledExecutorService scheduler = mock(ScheduledExecutorService.class);

        new PlaintextMigrationBanner(false, "", scheduler).start();

        verifyNoInteractions(scheduler);
    }

    @Test
    void theBannerNamesTheFlagAndTheEndDate() {
        assertThat(PlaintextMigrationBanner.banner("2026-10-30"))
                .contains("HELIX_DB_ENCRYPTION_MIGRATE_PLAINTEXT").contains("2026-10-30");
    }
}
