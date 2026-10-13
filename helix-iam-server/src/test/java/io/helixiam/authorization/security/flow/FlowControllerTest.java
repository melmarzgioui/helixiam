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

    @org.junit.jupiter.api.BeforeEach
    void thePendingSignInIsTheFlowsUser() {
        // the flow's own user is pending in this session (MfaService.unlockUser(expected) promotes only that one)
        when(mfaService.unlockUser("user-9")).thenReturn(true);
    }

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
     * Task 3 (fix round 1 — stale acr): a federated login that needed a step-up ({@link
     * io.helixiam.authorization.federation.FederatedLoginCompleter} CHALLENGE branch) holds the asserted
     * LoA only as {@link FlowExecutionState#pendingAcr()} — never directly in the live {@code HELIX_ACR}
     * session attribute. This endpoint must promote it to {@code HELIX_ACR} once THIS SAME flow reaches
     * COMPLETED (after the session-id rotation and the auth_time stamp), so it still reaches the
     * authorization once the resumed {@code /oauth2/authorize} issues the code.
     */
    @Test
    void completingTheChallenge_promotesThePendingAcrFromAFederatedStepUp() {
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.submit(any(), any(), any(), any())).thenReturn(FlowProgress.completed("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final HttpSession session = request.getSession(true);

        final FlowExecutionState state = new FlowExecutionState("master");
        state.setUserId("user-9");
        state.setCurrentChallengeExecutionId("otp-exec");
        state.setPendingAcr("http://eidas.europa.eu/LoA/substantial"); // stashed by FederatedLoginCompleter
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE, new AuthFlowDefinition());

        // No HELIX_ACR before completion: the pending value is held only on the flow state.
        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE)).isNull();

        final String view = controller.submitChallenge(Map.of("code", "123456"), session,
                new ExtendedModelMap(), request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
    }

    /** A flow with no pending acr (e.g. a plain password step-up) promotes none. */
    @Test
    void completingTheChallenge_withNoPendingAcr_setsNoAcr() {
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.submit(any(), any(), any(), any())).thenReturn(FlowProgress.completed("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final HttpSession session = request.getSession(true);

        final FlowExecutionState state = new FlowExecutionState("master");
        state.setUserId("user-9");
        state.setCurrentChallengeExecutionId("otp-exec");
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE, new AuthFlowDefinition());

        controller.submitChallenge(Map.of("code", "123456"), session, new ExtendedModelMap(), request, response);

        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE)).isNull();
    }
}
