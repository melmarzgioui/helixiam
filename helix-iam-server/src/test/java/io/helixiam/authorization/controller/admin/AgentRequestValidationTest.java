/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The admin API refuses an agent role in the reserved FACTOR_ namespace (realm role or clientId/role), any case. */
class AgentRequestValidationTest {

    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void factorNamedRoles_areRefused_otherRolesAreNot() {
        for (final String roles : new String[] {"FACTOR_PASSWORD", "reader, FACTOR_PASSWORD", "reader factor_ott",
                "billing/FACTOR_X", "reader,billing/factor_y"}) {
            assertThat(validator.validateValue(AgentIdentityAdminController.AgentRequest.class, "roles", roles))
                    .as(roles).singleElement()
                    .satisfies(v -> assertThat(v.getMessage()).contains("FACTOR_"));
        }
        for (final String roles : new String[] {"reader", "reader, billing/writer", "myfactor_role", "factory", ""}) {
            assertThat(validator.validateValue(AgentIdentityAdminController.AgentRequest.class, "roles", roles))
                    .as(roles).isEmpty();
        }
        assertThat(validator.validateValue(AgentIdentityAdminController.AgentRequest.class, "roles", null)).isEmpty();
    }
}
