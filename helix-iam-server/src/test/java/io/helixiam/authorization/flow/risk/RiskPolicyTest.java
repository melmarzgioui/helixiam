/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.risk;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Helix IAM (adaptive auth): policy banding + the default-OFF policy. */
class RiskPolicyTest {

    @Test
    void disabledPolicy_isOff() {
        assertThat(RiskPolicy.disabled().enabled()).isFalse();
    }

    @Test
    void bandsByThreshold() {
        RiskPolicy p = new RiskPolicy(true, 40, 70,
                RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);

        assertThat(p.band(0)).isEqualTo(RiskBand.LOW);
        assertThat(p.band(39)).isEqualTo(RiskBand.LOW);
        assertThat(p.band(40)).isEqualTo(RiskBand.MEDIUM);
        assertThat(p.band(69)).isEqualTo(RiskBand.MEDIUM);
        assertThat(p.band(70)).isEqualTo(RiskBand.HIGH);
        assertThat(p.band(100)).isEqualTo(RiskBand.HIGH);
    }

    @Test
    void mapsBandToAction() {
        RiskPolicy p = new RiskPolicy(true, 40, 70,
                RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);

        assertThat(p.actionFor(RiskBand.LOW)).isEqualTo(RiskAction.ALLOW);
        assertThat(p.actionFor(RiskBand.MEDIUM)).isEqualTo(RiskAction.STEP_UP);
        assertThat(p.actionFor(RiskBand.HIGH)).isEqualTo(RiskAction.DENY);
    }

    @Test
    void actionFromString_isLenient() {
        assertThat(RiskAction.fromString("challenge")).isEqualTo(RiskAction.STEP_UP);
        assertThat(RiskAction.fromString("STEP_UP")).isEqualTo(RiskAction.STEP_UP);
        assertThat(RiskAction.fromString("deny")).isEqualTo(RiskAction.DENY);
        assertThat(RiskAction.fromString("allow")).isEqualTo(RiskAction.ALLOW);
        assertThat(RiskAction.fromString(null)).isEqualTo(RiskAction.ALLOW);
        assertThat(RiskAction.fromString("nonsense")).isEqualTo(RiskAction.ALLOW);
    }
}
