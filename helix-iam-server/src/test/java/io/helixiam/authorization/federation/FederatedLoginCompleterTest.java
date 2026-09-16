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
}
