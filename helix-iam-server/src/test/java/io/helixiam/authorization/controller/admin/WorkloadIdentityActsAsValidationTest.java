/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM WIF: the "acts as" identity must be a real OIDC client in the realm with its service account
 * enabled (i.e. the {@code client_credentials} grant). {@link WorkloadIdentityAdminController#actsAsError}
 * is the pure guardrail behind the create/update endpoints — null grant types means no such client.
 */
class WorkloadIdentityActsAsValidationTest {

    @Test
    void acceptsAServiceAccountClient() {
        assertThat(WorkloadIdentityAdminController.actsAsError(List.of("client_credentials"))).isNull();
        assertThat(WorkloadIdentityAdminController.actsAsError(List.of("authorization_code", "client_credentials")))
                .isNull();
    }

    @Test
    void rejectsAnUnknownClient() {
        assertThat(WorkloadIdentityAdminController.actsAsError(null)).contains("was not found");
    }

    @Test
    void rejectsAClientWithoutServiceAccountEnabled() {
        assertThat(WorkloadIdentityAdminController.actsAsError(List.of("authorization_code")))
                .contains("service account");
    }
}
