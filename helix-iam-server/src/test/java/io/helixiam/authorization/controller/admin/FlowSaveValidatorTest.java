/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** A flow save names the verify-only wallet connection of every wallet verification step. */
class FlowSaveValidatorTest {

    private static FlowExecutionDto step(final String authenticator, final Map<String, String> config) {
        return new FlowExecutionDto("e1", null, authenticator, "REQUIRED", false, 10, config);
    }

    @Test
    void aWalletVerificationStep_needsItsConnection() {
        assertThat(FlowSaveValidator.validate(List.of(step("password", null),
                step("eudi-wallet-verify", Map.of())))).containsOnlyKeys("executions[1].config.providerAlias");
        assertThat(FlowSaveValidator.validate(List.of(step("eudi-wallet-verify", Map.of("providerAlias", "a b")))))
                .containsKey("executions[0].config.providerAlias");
        assertThat(FlowSaveValidator.validate(List.of(step("eudi-wallet-verify", null))))
                .containsKey("executions[0].config.providerAlias");
        assertThatThrownBy(() -> FlowSaveValidator.requireValid(List.of(step("eudi-wallet-verify", Map.of()))))
                .isInstanceOf(ProviderValidationException.class);
    }

    @Test
    void otherStepsAndANamedConnection_areValid() {
        assertThat(FlowSaveValidator.validate(List.of(step("password", null), step("otp", Map.of()),
                step("eudi-wallet-verify", Map.of("providerAlias", "eudi-verify"))))).isEmpty();
    }
}
