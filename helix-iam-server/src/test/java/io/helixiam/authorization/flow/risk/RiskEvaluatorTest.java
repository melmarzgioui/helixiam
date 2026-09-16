/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.risk;

import io.helixiam.authorization.amqp.risk.RiskSignals;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM (adaptive auth): the risk-scoring engine is pure — known device/IP score low, new
 * device/IP/velocity/new-country push the score up and band it under the realm policy.
 */
class RiskEvaluatorTest {

    private final RiskEvaluator evaluator = new RiskEvaluator();
    private final RiskPolicy policy = new RiskPolicy(true, 40, 70,
            RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);

    private RiskSignals signals(final boolean hasDevices, final boolean knownDevice,
                                final boolean hasHistory, final boolean knownIp,
                                final int failures, final boolean newCountry) {
        final RiskSignals s = new RiskSignals();
        s.setHasEnrolledDevices(hasDevices);
        s.setKnownDevice(knownDevice);
        s.setHasLoginHistory(hasHistory);
        s.setKnownIp(knownIp);
        s.setRecentFailureCount(failures);
        s.setNewCountry(newCountry);
        return s;
    }

    @Test
    void knownDeviceAndKnownIp_scoreZero_low_allow() {
        RiskAssessment a = evaluator.evaluate(
                signals(true, true, true, true, 0, false), policy);

        assertThat(a.score()).isZero();
        assertThat(a.band()).isEqualTo(RiskBand.LOW);
        assertThat(a.action()).isEqualTo(RiskAction.ALLOW);
        assertThat(a.reasons()).isEmpty();
    }

    @Test
    void brandNewUserWithNoHistory_isNotPenalised() {
        // No enrolled devices and no login history → new device/IP signals are suppressed.
        RiskAssessment a = evaluator.evaluate(
                signals(false, false, false, false, 0, false), policy);

        assertThat(a.score()).isZero();
        assertThat(a.band()).isEqualTo(RiskBand.LOW);
    }

    @Test
    void newDevice_addsDeviceWeight() {
        RiskAssessment a = evaluator.evaluate(
                signals(true, false, true, true, 0, false), policy);

        assertThat(a.score()).isEqualTo(RiskEvaluator.WEIGHT_NEW_DEVICE);
        assertThat(a.reasons()).anyMatch(r -> r.contains("device"));
    }

    @Test
    void newDeviceAndNewIp_bandsMedium_stepUp() {
        // 35 + 25 = 60 → between mediumThreshold(40) and highThreshold(70).
        RiskAssessment a = evaluator.evaluate(
                signals(true, false, true, false, 0, false), policy);

        assertThat(a.score()).isEqualTo(60);
        assertThat(a.band()).isEqualTo(RiskBand.MEDIUM);
        assertThat(a.action()).isEqualTo(RiskAction.STEP_UP);
    }

    @Test
    void failureVelocity_isWeightedAndCapped() {
        // 5 failures * 15 = 75 but capped at 45.
        RiskAssessment a = evaluator.evaluate(
                signals(true, true, true, true, 5, false), policy);

        assertThat(a.score()).isEqualTo(RiskEvaluator.MAX_FAILURE_CONTRIBUTION);
    }

    @Test
    void newDeviceNewIpAndNewCountry_bandsHigh_deny() {
        // 35 + 25 + 25 = 85 → >= highThreshold(70).
        RiskAssessment a = evaluator.evaluate(
                signals(true, false, true, false, 0, true), policy);

        assertThat(a.score()).isEqualTo(85);
        assertThat(a.band()).isEqualTo(RiskBand.HIGH);
        assertThat(a.action()).isEqualTo(RiskAction.DENY);
    }

    @Test
    void scoreIsClampedTo100() {
        RiskAssessment a = evaluator.evaluate(
                signals(true, false, true, false, 9, true), policy);

        assertThat(a.score()).isEqualTo(100);
    }

    @Test
    void newCountrySignalIgnoredWhenNoGeo() {
        // newCountry is false (no geo source) → no contribution even with new device.
        RiskAssessment a = evaluator.evaluate(
                signals(true, false, true, true, 0, false), policy);

        assertThat(a.score()).isEqualTo(RiskEvaluator.WEIGHT_NEW_DEVICE);
        assertThat(a.reasons()).noneMatch(r -> r.contains("country"));
    }
}
