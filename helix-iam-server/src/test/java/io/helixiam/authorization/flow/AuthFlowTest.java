/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.2/E2.4: the runtime resolves the execution the engine names (to find its
 * authenticator id), including executions nested inside CONDITIONAL sub-flows.
 */
class AuthFlowTest {

    private AuthFlow nestedFlow() {
        return AuthFlow.of("browser",
                AuthExecution.authenticator("e-pass", "password", Requirement.REQUIRED),
                AuthExecution.subFlow("e-stepup", Requirement.CONDITIONAL,
                        AuthFlow.of("stepup",
                                AuthExecution.condition("c-risk", "risk-high"),
                                AuthExecution.authenticator("e-otp", "otp", Requirement.REQUIRED))));
    }

    @Test
    void findsATopLevelExecutionById() {
        Optional<AuthExecution> found = nestedFlow().findExecution("e-pass");

        assertThat(found).isPresent();
        assertThat(found.get().authenticatorId()).isEqualTo("password");
    }

    @Test
    void findsAnExecutionNestedInsideASubflow() {
        Optional<AuthExecution> found = nestedFlow().findExecution("e-otp");

        assertThat(found).isPresent();
        assertThat(found.get().authenticatorId()).isEqualTo("otp");
    }

    @Test
    void unknownExecutionId_isEmpty() {
        assertThat(nestedFlow().findExecution("nope")).isEmpty();
    }
}
