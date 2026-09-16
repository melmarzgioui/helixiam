/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.saml;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E5.2 follow-up: the SAML assertion replay cache enforces one-time use of an assertion ID
 * within its validity window. First sighting is recorded (accepted); a repeat within the window is a
 * replay (rejected); once the window has passed the id is forgotten so the cache stays bounded.
 */
class InMemorySamlAssertionReplayCacheTest {

    private final InMemorySamlAssertionReplayCache cache = new InMemorySamlAssertionReplayCache();

    @Test
    void firstSightingIsAcceptedAndRecorded() {
        assertThat(cache.checkAndRecord("_a1", Instant.now().plus(5, ChronoUnit.MINUTES))).isTrue();
    }

    @Test
    void aRepeatWithinTheWindowIsRejected() {
        final Instant expiry = Instant.now().plus(5, ChronoUnit.MINUTES);
        cache.checkAndRecord("_a1", expiry);

        assertThat(cache.checkAndRecord("_a1", expiry)).isFalse();
    }

    @Test
    void anExpiredIdIsForgottenAndAcceptedAgain() {
        cache.checkAndRecord("_a1", Instant.now().minus(1, ChronoUnit.SECONDS)); // already expired

        // The window has passed, so the same id is no longer considered a live replay.
        assertThat(cache.checkAndRecord("_a1", Instant.now().plus(5, ChronoUnit.MINUTES))).isTrue();
    }

    @Test
    void distinctIdsAreIndependent() {
        final Instant expiry = Instant.now().plus(5, ChronoUnit.MINUTES);
        assertThat(cache.checkAndRecord("_a1", expiry)).isTrue();
        assertThat(cache.checkAndRecord("_a2", expiry)).isTrue();
    }
}
