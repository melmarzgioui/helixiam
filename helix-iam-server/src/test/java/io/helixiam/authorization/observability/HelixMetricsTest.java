/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.observability;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

class HelixMetricsTest {

    private MeterRegistry registry;
    private HelixMetrics metrics;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new HelixMetrics(registry);
    }

    private double count(final String name, final String... tags) {
        var search = registry.find(name);
        for (int i = 0; i + 1 < tags.length; i += 2) {
            search = search.tag(tags[i], tags[i + 1]);
        }
        var counter = search.counter();
        return counter == null ? -1d : counter.count();
    }

    @Test
    void recordLogin_incrementsCounterWithRealmAndOutcomeTags() {
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "success");
        metrics.recordLogin("master", "failure");

        assertThat(count(HelixMetrics.LOGIN_TOTAL, "realm", "master", "outcome", "success")).isEqualTo(2d);
        assertThat(count(HelixMetrics.LOGIN_TOTAL, "realm", "master", "outcome", "failure")).isEqualTo(1d);
    }

    @Test
    void recordTokenIssued_tagsByGrantType() {
        metrics.recordTokenIssued("master", "authorization_code");
        metrics.recordTokenIssued("master", "client_credentials");
        metrics.recordTokenIssued("master", "client_credentials");

        assertThat(count(HelixMetrics.TOKENS_ISSUED_TOTAL, "realm", "master", "grant_type", "authorization_code")).isEqualTo(1d);
        assertThat(count(HelixMetrics.TOKENS_ISSUED_TOTAL, "realm", "master", "grant_type", "client_credentials")).isEqualTo(2d);
    }

    @Test
    void recordMfaChallenge_tagsOutcome() {
        metrics.recordMfaChallenge("master", "success");
        metrics.recordMfaChallenge("master", "failure");

        assertThat(count(HelixMetrics.MFA_CHALLENGE_TOTAL, "realm", "master", "outcome", "success")).isEqualTo(1d);
        assertThat(count(HelixMetrics.MFA_CHALLENGE_TOTAL, "realm", "master", "outcome", "failure")).isEqualTo(1d);
    }

    @Test
    void recordAdminWrite_tagsMethodAndOutcome() {
        metrics.recordAdminWrite("master", "POST", "success");
        metrics.recordAdminWrite("master", "DELETE", "denied");

        assertThat(count(HelixMetrics.ADMIN_WRITE_TOTAL, "realm", "master", "method", "POST", "outcome", "success")).isEqualTo(1d);
        assertThat(count(HelixMetrics.ADMIN_WRITE_TOTAL, "realm", "master", "method", "DELETE", "outcome", "denied")).isEqualTo(1d);
    }

    @Test
    void nullRealmAndOutcome_normalisedToUnknown_keepingCardinalityBounded() {
        metrics.recordLogin(null, null);

        assertThat(count(HelixMetrics.LOGIN_TOTAL, "realm", "unknown", "outcome", "unknown")).isEqualTo(1d);
    }

    @Test
    void metricsFailure_isSwallowed_neverThrowsIntoAuthPath() {
        // A registry that throws on every meter registration simulates a broken metrics backend.
        final MeterRegistry hostile = Mockito.mock(MeterRegistry.class, invocation -> {
            throw new IllegalStateException("metrics backend down");
        });
        final HelixMetrics hardened = new HelixMetrics(hostile);

        // Must not propagate — the auth path keeps running.
        hardened.recordLogin("master", "success");
        hardened.recordTokenIssued("master", "authorization_code");
        hardened.recordMfaChallenge("master", "failure");
        hardened.recordAdminWrite("master", "POST", "success");
        // Reaching here without an exception is the assertion.
        assertThat(true).isTrue();
    }
}
