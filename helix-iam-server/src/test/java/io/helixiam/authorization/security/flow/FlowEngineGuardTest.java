/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.flow.persistence.AuthExecutionDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Security review item 3a: a login whose flow has the wallet verification step needs the flow engine. */
class FlowEngineGuardTest {

    private static AuthFlowDefinition flow(final String... authenticators) {
        final AuthFlowDefinition d = mock(AuthFlowDefinition.class);
        final List<AuthExecutionDefinition> executions = new java.util.ArrayList<>();
        for (final String a : authenticators) {
            final AuthExecutionDefinition e = new AuthExecutionDefinition();
            e.setAuthenticatorId(a);
            executions.add(e);
        }
        when(d.getExecutions()).thenReturn(executions);
        return d;
    }

    @Test
    void theClientsFlowOrTheRealmsBrowserFlow_decides() {
        final AuthFlowPublisher flows = mock(AuthFlowPublisher.class);
        final AuthFlowDefinition stepUp = flow("otp", "eudi-wallet-verify");
        final AuthFlowDefinition plain = flow("otp");
        final AuthFlowDefinition walletOnly = flow("eudi-wallet-verify");
        when(flows.retrieveFlowForClient(anyString())).thenReturn(stepUp);
        when(flows.retrieveBrowserFlow("acme")).thenReturn(plain);
        assertThat(FlowEngineGuard.needsEngine(flows, "acme", "bank")).isTrue();
        assertThat(FlowEngineGuard.needsEngine(flows, "acme", null)).isFalse();
        when(flows.retrieveBrowserFlow("acme")).thenReturn(walletOnly);
        assertThat(FlowEngineGuard.needsEngine(flows, "acme", " ")).isTrue();
        when(flows.retrieveBrowserFlow("acme")).thenThrow(new IllegalStateException("down"));
        assertThat(FlowEngineGuard.needsEngine(flows, "acme", null)).isFalse();
    }
}
