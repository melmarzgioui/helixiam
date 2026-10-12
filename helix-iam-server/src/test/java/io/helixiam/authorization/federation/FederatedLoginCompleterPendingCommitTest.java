/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.AuthFlow;
import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.FlowProgress;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.security.flow.FlowLoginSuccessHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.Serializable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Task 18: a federated login can carry a pending commit (the EUDI wallet's upgrade link) that is made only once the
 * post-broker flow has completed, right before the session is established; a commit that refuses ends the login with
 * no session. On a step-up the commit waits in the flow state for {@code FlowController}.
 */
class FederatedLoginCompleterPendingCommitTest {

    private static final String SP = "https://helix.test";
    private static final String USER_ID = "user-9";
    private static final Serializable PENDING = "pending-link";

    private final FlowExecutor flowExecutor = mock(FlowExecutor.class);
    private final AuthFlowPublisher authFlowPublisher = mock(AuthFlowPublisher.class);
    private final AuthFlowMapper authFlowMapper = mock(AuthFlowMapper.class);
    private final FederatedSessionEstablisher establisher = mock(FederatedSessionEstablisher.class);
    private final FederatedLoginCommit commit = mock(FederatedLoginCommit.class);

    private final FederatedLoginCompleter completer = new FederatedLoginCompleter(
            flowExecutor, authFlowPublisher, authFlowMapper, establisher, SP,
            new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                    mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)));

    @BeforeEach
    void wire() throws Exception {
        completer.setLoginCommit(commit);
        when(establisher.loadUser(USER_ID)).thenReturn(new ObjectMapper().readValue(
                "{\"userId\":\"" + USER_ID + "\",\"username\":\"ada@corp\",\"authorities\":[{\"role\":\"ROLE_USER\"}]}",
                UserCredentials.class));
        when(authFlowPublisher.retrieveBrowserFlow(any())).thenReturn(null);
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void completedFlow_commitsBeforeTheSessionIsEstablished() {
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.completed(USER_ID));
        when(commit.commit(PENDING, USER_ID)).thenReturn(true);

        final String view = completer.complete(USER_ID, null, new MockHttpServletRequest(),
                new MockHttpServletResponse(), PENDING);

        assertThat(view).isEqualTo("redirect:" + SP);
        verify(commit).commit(PENDING, USER_ID);
        verify(establisher).persist(any(), any(), any());
    }

    @Test
    void aRefusedCommit_endsTheLoginWithoutASession() {
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.completed(USER_ID));
        when(commit.commit(PENDING, USER_ID)).thenReturn(false);
        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String view = completer.complete(USER_ID, null, request, new MockHttpServletResponse(), PENDING);

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        verify(establisher, never()).persist(any(), any(), any());
        assertThat(request.getSession().getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE)).isNull();
    }

    @Test
    void aStepUp_holdsTheCommitInTheFlowState_withoutMakingIt() {
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.challenge("otp-form", "browser-otp"));
        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String view = completer.complete(USER_ID, null, request, new MockHttpServletResponse(), PENDING);

        assertThat(view).isEqualTo("redirect:/flow");
        verifyNoInteractions(commit);
        final FlowExecutionState state = (FlowExecutionState) request.getSession()
                .getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
        assertThat(state.pendingCommit()).isEqualTo(PENDING);
    }

    @Test
    void aFailedFlow_neverCommits() {
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.failed());

        assertThat(completer.complete(USER_ID, null, new MockHttpServletRequest(), new MockHttpServletResponse(),
                PENDING)).isEqualTo("redirect:/login?error=federation");
        verifyNoInteractions(commit);
    }

    @Test
    void withoutACommitter_aPendingCommitRefusesTheLogin() {
        final FederatedLoginCompleter bare = new FederatedLoginCompleter(flowExecutor, authFlowPublisher,
                authFlowMapper, establisher, SP, new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)));
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.completed(USER_ID));

        assertThat(bare.complete(USER_ID, null, new MockHttpServletRequest(), new MockHttpServletResponse(), PENDING))
                .isEqualTo("redirect:/login?error=federation");
        verify(establisher, never()).persist(any(), any(), any());
    }
}
