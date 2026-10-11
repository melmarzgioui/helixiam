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
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5.4: post-broker step-up. After the broker resolves the user, the completer runs the
 * realm's post-(primary-auth) flow — the SAME MFA flow the password path runs — so a federated login
 * can still be forced through MFA. The flow completing immediately establishes a full session; a
 * flow that challenges holds a non-authenticated {@link MfaAuthentication} gate and routes to /flow.
 */
class FederatedLoginCompleterTest {

    private static final String SP = "https://helix.test";
    private static final String USER_ID = "user-9";

    private final FlowExecutor flowExecutor = mock(FlowExecutor.class);
    private final AuthFlowPublisher authFlowPublisher = mock(AuthFlowPublisher.class);
    private final AuthFlowMapper authFlowMapper = mock(AuthFlowMapper.class);
    private final FederatedSessionEstablisher establisher = mock(FederatedSessionEstablisher.class);

    private final FederatedLoginCompleter completer = new FederatedLoginCompleter(
            flowExecutor, authFlowPublisher, authFlowMapper, establisher, SP,
            new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                    mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)));

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static UserCredentials user(final String id) throws Exception {
        return new ObjectMapper().readValue(
                "{\"userId\":\"" + id + "\",\"username\":\"ada@corp\",\"authorities\":[{\"role\":\"ROLE_USER\"}]}",
                UserCredentials.class);
    }

    /** Stubs a federated login whose post-broker flow completes immediately (no step-up). */
    private void givenFlowCompletes() {
        try {
            when(establisher.loadUser(USER_ID)).thenReturn(user(USER_ID));
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        when(authFlowPublisher.retrieveBrowserFlow(any())).thenReturn(null); // use the in-code fallback
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.completed(USER_ID));
    }

    @Test
    void completedFlowEstablishesAFullSessionAndRedirectsToTheSp() throws Exception {
        when(establisher.loadUser("user-9")).thenReturn(user("user-9"));
        when(authFlowPublisher.retrieveBrowserFlow(any())).thenReturn(null); // use the in-code fallback
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.completed("user-9"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = completer.complete("user-9", request, response);

        assertThat(view).isEqualTo("redirect:" + SP);
        final ArgumentCaptor<Authentication> auth = ArgumentCaptor.forClass(Authentication.class);
        verify(establisher).persist(auth.capture(), any(), any());
        assertThat(auth.getValue().isAuthenticated()).isTrue();
        assertThat(auth.getValue().getName()).isEqualTo("user-9");
    }

    @Test
    void challengingFlowHoldsAnMfaGateAndRoutesToFlow() throws Exception {
        when(establisher.loadUser("user-9")).thenReturn(user("user-9"));
        when(authFlowPublisher.retrieveBrowserFlow(any())).thenReturn(null);
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.challenge("otp-form", "browser-otp"));

        final MockHttpServletRequest request = new MockHttpServletRequest();
        final MockHttpServletResponse response = new MockHttpServletResponse();

        final String view = completer.complete("user-9", request, response);

        assertThat(view).isEqualTo("redirect:/flow");
        final ArgumentCaptor<Authentication> auth = ArgumentCaptor.forClass(Authentication.class);
        verify(establisher).persist(auth.capture(), any(), any());
        assertThat(auth.getValue()).isInstanceOf(MfaAuthentication.class);
        assertThat(auth.getValue().isAuthenticated()).isFalse();
        // The flow state + definition are stashed for the /flow controller to continue.
        assertThat(request.getSession().getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE))
                .isInstanceOf(FlowExecutionState.class);
        assertThat(request.getSession().getAttribute(FlowLoginSuccessHandler.FLOW_DEFINITION_ATTRIBUTE)).isNotNull();
    }

    @Test
    void failedFlowRejectsWithoutEstablishingASession() throws Exception {
        when(establisher.loadUser("user-9")).thenReturn(user("user-9"));
        when(authFlowPublisher.retrieveBrowserFlow(any())).thenReturn(null);
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.failed());

        final String view = completer.complete("user-9", new MockHttpServletRequest(), new MockHttpServletResponse());

        assertThat(view).startsWith("redirect:/login?error");
        verify(establisher, never()).persist(any(), any(), any());
    }

    @Test
    void completedFederatedLogin_rotatesTheSessionId_beforePersistingTheContext() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final String before = request.getSession(true).getId();
        givenFlowCompletes();                       // existing helper in this test class
        completer.complete(USER_ID, request, new MockHttpServletResponse());
        assertThat(request.getSession(false).getId()).isNotEqualTo(before);
    }

    /**
     * Task 3: the brokered level of assurance (eID SAML {@code loa} attribute / the stub's {@code loa}
     * param) is carried into the session as {@code HELIX_ACR} so {@link
     * io.helixiam.authorization.security.session.SsoSessionBindingAuthorizationService} can bind it onto
     * the authorization the same way it binds {@code sid}/{@code auth_time}.
     */
    @Test
    void completedFederatedLoginWithAcr_putsAcrInTheSessionAfterRotation() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        givenFlowCompletes();

        completer.complete(USER_ID, "http://eidas.europa.eu/LoA/substantial", request, new MockHttpServletResponse());

        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
    }

    @Test
    void completedFederatedLoginWithoutAcr_leavesNoAcrInTheSession() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        givenFlowCompletes();

        completer.complete(USER_ID, request, new MockHttpServletResponse()); // old signature: delegates with null acr

        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE)).isNull();
    }

    /**
     * [Important fix round 1] Stale acr: a COMPLETED federated login must CLEAR a stale {@code HELIX_ACR}
     * an EARLIER login in this same browser session left behind, not just leave it when this one asserts
     * none. {@code authTimeStamper.stamp(request)} is the choke point that clears it — this proves the
     * completer actually goes through it before (not instead of) deciding whether to set a fresh value.
     */
    @Test
    void completedFederatedLoginWithoutAcr_clearsAStaleAcrFromAnEarlierLoginInThisSession() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute(
                io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE,
                "http://eidas.europa.eu/LoA/high"); // stale, from an earlier high-LoA login
        givenFlowCompletes();

        completer.complete(USER_ID, request, new MockHttpServletResponse()); // this login asserts no LoA

        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE)).isNull();
    }

    /** Same stale-clearing choke point, but this login DOES assert a (different, lower) LoA. */
    @Test
    void completedFederatedLoginWithAcr_replacesAStaleAcrFromAnEarlierLoginInThisSession() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute(
                io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE,
                "http://eidas.europa.eu/LoA/high"); // stale, from an earlier high-LoA login
        givenFlowCompletes();

        completer.complete(USER_ID, "http://eidas.europa.eu/LoA/substantial", request, new MockHttpServletResponse());

        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE))
                .isEqualTo("http://eidas.europa.eu/LoA/substantial");
    }

    /**
     * [Important fix round 1] The step-up (CHALLENGE) path: the asserted LoA is held ONLY on {@link
     * FlowExecutionState#pendingAcr()} — never written directly to the live {@code HELIX_ACR} session
     * attribute. That means an abandoned challenge has NOTHING to leak: a later, unrelated login in this
     * browser (which always gets its own brand-new {@code FlowExecutionState}, see {@code
     * FlowLoginSuccessHandler}) can never see it. {@code FlowController} is what promotes it, and only when
     * THIS SAME flow reaches COMPLETED (covered by {@code FlowControllerTest}).
     */
    @Test
    void challengingFederatedLoginWithAcr_holdsItOnlyAsPendingOnTheFlowState_neverInTheLiveSession() throws Exception {
        when(establisher.loadUser("user-9")).thenReturn(user("user-9"));
        when(authFlowPublisher.retrieveBrowserFlow(any())).thenReturn(null);
        when(authFlowMapper.toAuthFlow(any())).thenReturn(AuthFlow.of("browser"));
        when(flowExecutor.begin(any(), any())).thenReturn(FlowProgress.challenge("otp-form", "browser-otp"));

        final MockHttpServletRequest request = new MockHttpServletRequest();

        final String view = completer.complete("user-9", "http://eidas.europa.eu/LoA/substantial", request,
                new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:/flow");
        // NOT in the live session attribute — nothing to leak to an unrelated later login.
        assertThat(request.getSession(false)
                .getAttribute(io.helixiam.authorization.security.session.AuthTimeStamper.ACR_SESSION_ATTRIBUTE)).isNull();
        // Held as pending on THIS flow's state, ready for FlowController to promote on completion.
        final FlowExecutionState state = (FlowExecutionState) request.getSession(false)
                .getAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE);
        assertThat(state.pendingAcr()).isEqualTo("http://eidas.europa.eu/LoA/substantial");
    }
}
