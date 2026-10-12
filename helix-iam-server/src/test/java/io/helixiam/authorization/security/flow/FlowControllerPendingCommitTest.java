/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.federation.FederatedLoginCommit;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ExtendedModelMap;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Task 18: a federated login's pending commit (held in the flow state by {@code FederatedLoginCompleter} on a
 * step-up) is made when, and only when, this flow completes; a refused commit ends the login and leaves no session.
 */
class FlowControllerPendingCommitTest {

    private static final String SP = "https://helix.test";

    private final FlowExecutor flowExecutor = mock(FlowExecutor.class);
    private final AuthFlowMapper authFlowMapper = mock(AuthFlowMapper.class);
    private final MfaService mfaService = mock(MfaService.class);
    private final FederatedLoginCommit commit = mock(FederatedLoginCommit.class);

    private final FlowController controller = new FlowController(flowExecutor, authFlowMapper, mfaService, SP,
            "localhost", new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                    mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)));

    @AfterEach
    void clear() {
        io.helixiam.authorization.security.realm.RealmContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest pending(final FlowProgress progress) {
        controller.setLoginCommits(java.util.List.of(commit));
        when(commit.supports("pending-link")).thenReturn(true);
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.submit(any(), any(), any(), any())).thenReturn(progress);
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final HttpSession session = request.getSession(true);
        final FlowExecutionState state = new FlowExecutionState("master");
        state.setUserId("user-9");
        state.setCurrentChallengeExecutionId("otp-exec");
        state.setCurrentChallengeView("otp-form");
        state.setPendingCommit("pending-link");
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE, new AuthFlowDefinition());
        return request;
    }

    @Test
    void completing_makesThePendingCommit_thenSignsIn() {
        final MockHttpServletRequest request = pending(FlowProgress.completed("user-9"));
        when(commit.commit("pending-link", "user-9")).thenReturn(true);

        final String view = controller.submitChallenge(Map.of("code", "123456"), request.getSession(),
                new ExtendedModelMap(), request, new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:" + SP);
        final org.mockito.InOrder order = org.mockito.Mockito.inOrder(mfaService, commit);
        order.verify(mfaService).unlockUser(); // the session is promoted first...
        order.verify(commit).commit("pending-link", "user-9"); // ...then the commit
    }

    @Test
    void aRefusedCommit_endsTheLogin_andDropsTheHalfSignedInSession() {
        final MockHttpServletRequest request = pending(FlowProgress.completed("user-9"));
        when(commit.commit("pending-link", "user-9")).thenReturn(false);
        final HttpSession session = request.getSession();

        final String view = controller.submitChallenge(Map.of("code", "123456"), session,
                new ExtendedModelMap(), request, new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        assertThat(request.getSession(false)).as("the half-signed-in session is gone").isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void aWrongSecondFactor_neverCommits() {
        final MockHttpServletRequest request = pending(FlowProgress.failed());

        controller.submitChallenge(Map.of("code", "000000"), request.getSession(), new ExtendedModelMap(), request,
                new MockHttpServletResponse());

        verify(commit, never()).commit(any(), any());
    }
}
