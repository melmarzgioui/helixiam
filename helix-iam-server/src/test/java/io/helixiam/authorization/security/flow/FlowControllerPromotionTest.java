/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.user.UserPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.FlowProgress;
import io.helixiam.authorization.flow.persistence.AuthFlowDefinition;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.service.MfaService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ExtendedModelMap;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * When the engine-driven flow completes, {@code /flow} promotes the pending (MFA-gated) authentication to a full
 * one. It must be the authentication of the user the flow completed for; otherwise nothing is promoted and the
 * session is dropped.
 */
class FlowControllerPromotionTest {

    private final FlowExecutor executor = mock(FlowExecutor.class);
    private final FlowController controller = new FlowController(executor, new AuthFlowMapper(),
            new MfaService(mock(UserPublisher.class)), "https://sp.test", "localhost",
            new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                    mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)));

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpSession pendingFlow(final String flowUser) {
        final MockHttpSession session = new MockHttpSession();
        final FlowExecutionState state = new FlowExecutionState("gov");
        state.setUserId(flowUser);
        state.setCurrentChallengeExecutionId("otp");
        state.setCurrentChallengeView("otp-form");
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        session.setAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE,
                new AuthFlowDefinition("browser", "gov", List.of()));
        return session;
    }

    private static void pendingAs(final String userId) throws Exception {
        final UserCredentials user = MfaEnabledConditionTest.user(userId, true);
        SecurityContextHolder.getContext().setAuthentication(new MfaAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities())));
    }

    private String submit(final MockHttpSession session) {
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/flow");
        request.setSession(session);
        return controller.submitChallenge(Map.of("code", "123456"), session, new ExtendedModelMap(), request,
                new MockHttpServletResponse());
    }

    @Test
    void thePendingAuthenticationOfTheFlowsUser_isPromoted() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        pendingAs("ada");

        final String view = submit(pendingFlow("ada"));

        final Authentication now = SecurityContextHolder.getContext().getAuthentication();
        assertThat(now.isAuthenticated()).isTrue();
        assertThat(now).isNotInstanceOf(MfaAuthentication.class);
        assertThat(view).doesNotContain("/login");
    }

    @Test
    void anotherUsersPendingAuthentication_isNotPromoted_andTheSessionIsDropped() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        pendingAs("bob");
        final MockHttpSession session = pendingFlow("ada");

        final String view = submit(session);

        final Authentication now = SecurityContextHolder.getContext().getAuthentication();
        assertThat(now == null || !now.isAuthenticated()).as("no full authentication").isTrue();
        assertThat(session.isInvalid()).isTrue();
        assertThat(view).contains("/login");
    }

    @Test
    void completingTheFlow_rotatesTheSessionId() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        pendingAs("ada");
        final MockHttpSession session = pendingFlow("ada");
        final String before = session.getId();

        submit(session);

        assertThat(session.getId()).as("a completed sign-in gets a new session id").isNotEqualTo(before);
    }

    /**
     * Final review M4: a flow user A left in this session (an abandoned wallet step-up carrying eIDAS high) must never
     * complete into a session that is now fully signed in as user B (e.g. by a magic link, which leaves no pending
     * authentication): nothing of A is promoted — not A's acr into B's session — and the session is dropped.
     */
    @Test
    void aStaleFlowOfUserA_neverPromotesAsAcrIntoUserBsSignedInSession() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        final UserCredentials bob = MfaEnabledConditionTest.user("bob", false);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(bob, null, bob.getAuthorities()));
        final MockHttpSession session = pendingFlow("ada");
        ((FlowExecutionState) session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE))
                .setPendingAcr("http://eidas.europa.eu/LoA/high");

        final String view = submit(session);

        assertThat(view).contains("/login");
        assertThat(session.isInvalid()).as("the session is dropped").isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).as("nothing stays signed in").isNull();
    }

    @Test
    void aCompletedFlow_leavesNoFlowStateBehind() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        pendingAs("ada");
        final MockHttpSession session = pendingFlow("ada");

        submit(session);

        assertThat(session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE)).isNull();
        assertThat(session.getAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE)).isNull();
    }

    /**
     * An admin-built flow whose challenge is not TOTP (email OTP, push, QR) completes for a user who has not enrolled
     * TOTP, in a realm that requires MFA: like {@link FlowLoginSuccessHandler}, no full session — the user goes to
     * enrolment with the pending sign-in (and the flow state that carries a federated login's commit) kept.
     */
    @Test
    void inAnMfaRequiredRealm_aCompletedFlowOfAUserNotEnrolled_goesToEnrolment_withoutAFullSession() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        final io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement enrolment =
                mock(io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement.class);
        when(enrolment.mustEnrol(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.eq("ada")))
                .thenReturn(true);
        controller.setMfaEnrolment(enrolment);
        pendingAs("ada");
        final MockHttpSession session = pendingFlow("ada");
        final Object state = session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
        final String before = session.getId();

        final String view = submit(session);

        assertThat(view).endsWith("/mfa/enable");
        final Authentication now = SecurityContextHolder.getContext().getAuthentication();
        assertThat(now).isInstanceOf(MfaAuthentication.class);
        assertThat(now.isAuthenticated()).as("no full session before enrolment").isFalse();
        assertThat(session.isInvalid()).isFalse();
        assertThat(session.getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE))
                .as("the pending state waits for the enrolment").isSameAs(state);
        assertThat(session.getId()).as("a new session id").isNotEqualTo(before);
    }

    @Test
    void theEnrolmentRule_neverHoldsAnotherUsersPendingSignIn() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        final io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement enrolment =
                mock(io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement.class);
        when(enrolment.mustEnrol(any(), anyString())).thenReturn(true);
        controller.setMfaEnrolment(enrolment);
        pendingAs("bob");
        final MockHttpSession session = pendingFlow("ada");

        final String view = submit(session);

        assertThat(view).contains("/login");
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void anEnrolledUser_inAnMfaRequiredRealm_completesToAFullSession() throws Exception {
        when(executor.submit(any(), any(), anyString(), anyMap())).thenReturn(FlowProgress.completed("ada"));
        controller.setMfaEnrolment(mock(io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement.class));
        pendingAs("ada");

        final String view = submit(pendingFlow("ada"));

        assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
        assertThat(view).doesNotContain("/mfa/");
    }
}
