/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.requiredactions;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** C3: VERIFY_EMAIL is pending exactly while verification is needed, and comes first. */
class RequiredActionsGateEmailTest {

    @Test
    void verifyEmailIsAddedFirstOrDropped() {
        assertThat(RequiredActionsGate.withEmailVerification(null, true)).isEqualTo("VERIFY_EMAIL");
        assertThat(RequiredActionsGate.withEmailVerification("UPDATE_PASSWORD", true)).isEqualTo("VERIFY_EMAIL,UPDATE_PASSWORD");
        assertThat(RequiredActionsGate.withEmailVerification("UPDATE_PASSWORD,VERIFY_EMAIL", true))
                .isEqualTo("VERIFY_EMAIL,UPDATE_PASSWORD");
        assertThat(RequiredActionsGate.withEmailVerification("VERIFY_EMAIL,UPDATE_PASSWORD", false)).isEqualTo("UPDATE_PASSWORD");
        assertThat(RequiredActionsGate.withEmailVerification("VERIFY_EMAIL", false)).isEmpty();
        assertThat(RequiredActionsGate.withEmailVerification(null, false)).isEmpty();
    }
}
