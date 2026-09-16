/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.risk;

/**
 * Helix IAM (adaptive auth): the per-realm risk policy — thresholds that band a numeric score and
 * the action to take per band. Read per-realm at login time from realm settings (no restart).
 *
 * <p><b>Default is OFF</b>: {@link #disabled()} yields a policy where {@link #enabled()} is false,
 * so the {@code RiskAuthenticator} passes straight through and existing logins are unchanged.
 *
 * <p>Scores run 0..100. A score {@code >= highThreshold} is {@link RiskBand#HIGH}; {@code >=
 * mediumThreshold} (but below high) is {@link RiskBand#MEDIUM}; anything lower is
 * {@link RiskBand#LOW}. Each band maps to a {@link RiskAction}.
 */
public record RiskPolicy(
        boolean enabled,
        int mediumThreshold,
        int highThreshold,
        RiskAction lowAction,
        RiskAction mediumAction,
        RiskAction highAction) {

    public static RiskPolicy disabled() {
        return new RiskPolicy(false, 40, 70, RiskAction.ALLOW, RiskAction.STEP_UP, RiskAction.DENY);
    }

    /** The band a numeric score falls into under this policy's thresholds. */
    public RiskBand band(final int score) {
        if (score >= highThreshold) {
            return RiskBand.HIGH;
        }
        if (score >= mediumThreshold) {
            return RiskBand.MEDIUM;
        }
        return RiskBand.LOW;
    }

    /** The action this policy takes for a given band. */
    public RiskAction actionFor(final RiskBand band) {
        return switch (band) {
            case HIGH -> highAction;
            case MEDIUM -> mediumAction;
            case LOW -> lowAction;
        };
    }
}
