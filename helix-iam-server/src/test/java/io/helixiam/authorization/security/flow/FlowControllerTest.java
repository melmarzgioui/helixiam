/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.flow.AuthFlow;
import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.FlowProgress;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.service.MfaService;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.ui.ExtendedModelMap;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E2.4/security: the generic post-challenge engine endpoint. A flow that COMPLETES here is the
 * SAME completion a federated post-broker step-up uses ({@link io.helixiam.authorization.federation.FederatedLoginCompleter}
 * routes to {@code /flow} on CHALLENGE); the session id must rotate exactly once when the second factor
 * passes, same as a federated login that needs no step-up.
 */
class FlowControllerTest {

    private static final String SP = "https://helix.test";

    private final FlowExecutor flowExecutor = mock(FlowExecutor.class);
    private final AuthFlowMapper authFlowMapper = mock(AuthFlowMapper.class);
    private final MfaService mfaService = mock(MfaService.class);

    private final FlowController controller = new FlowController(flowExecutor, authFlowMapper, mfaService, SP,
            "localhost", new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                    mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)));

    @AfterEach
    void clear() {
        io.helixiam.authorization.security.realm.RealmContextHolder.clear();
    }

    @Test
    void completingTheChallenge_rotatesTheSessionId_beforePromotingTheContext() {
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.submit(any(), any(), any(), any())).thenReturn(FlowProgress.completed("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final HttpSession session = request.getSession(true);
        final String before = session.getId();

        final FlowExecutionState state = new FlowExecutionState("master");
        state.setUserId("user-9");
        state.setCurrentChallengeExecutionId("otp-exec");
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE, new AuthFlowDefinition());

        final String view = controller.submitChallenge(Map.of("code", "123456"), session,
                new ExtendedModelMap(), request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        assertThat(request.getSession(false).getId()).isNotEqualTo(before);
    }

    /**
     * Task 3: a federated login that needed a step-up ({@link
     * io.helixiam.authorization.federation.FederatedLoginCompleter} CHALLENGE branch) stashes {@code
     * HELIX_ACR} in the session before routing here. This endpoint must not lose it when the second
     * factor passes and the session id rotates — it still needs to reach the authorization once the
     * resumed {@code /oauth2/authorize} issues the code.
     */
    @Test
    void completingTheChallenge_keepsTheAcrAFederatedLoginStashedBeforeTheStepUp() {
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.submit(any(), any(), any(), any())).thenReturn(FlowProgress.completed("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final HttpSession session = request.getSession(true);
        session.setAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE,
                "http://eidas.europa.eu/LoA/substantial");

        final FlowExecutionState state = new FlowExecutionState("master");
        state.setUserId("user-9");
        state.setCurrentChallengeExecutionId("otp-exec");
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE, new AuthFlowDefinition());

        final String view = controller.submitChallenge(Map.of("code", "123456"), session,
                new ExtendedModelMap(), request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
    }
}
