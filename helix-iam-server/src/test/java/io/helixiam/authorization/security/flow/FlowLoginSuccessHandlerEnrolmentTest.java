/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.AuthFlowPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.FlowExecutor;
import io.helixiam.authorization.flow.FlowProgress;
import io.helixiam.authorization.flow.persistence.AuthFlowMapper;
import io.helixiam.authorization.security.mfa.MfaEnrolmentRequirement;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The local password sign-in's post-password flow (used with the flow engine, and always to resume after required
 * actions): in a realm that requires MFA, a user who has not enrolled gets no full session when the flow completes,
 * but the enrolment step, like the magic-link and legacy password paths.
 */
class FlowLoginSuccessHandlerEnrolmentTest {

    private final FlowExecutor executor = mock(FlowExecutor.class);
    private final MfaEnrolmentRequirement enrolment = mock(MfaEnrolmentRequirement.class);
    private final FlowLoginSuccessHandler handler = new FlowLoginSuccessHandler(executor,
            mock(AuthFlowPublisher.class), new AuthFlowMapper(), "https://sp.test",
            new io.helixiam.authorization.security.realm.SessionPolicyApplier(
                    mock(io.helixiam.authorization.security.realm.RealmSettingsResolver.class)), null, enrolment);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static Authentication passwordAuth(final String userId) throws Exception {
        final UserCredentials user = MfaEnabledConditionTest.user(userId, false);
        return UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities());
    }

    @Test
    void inARealmThatRequiresMfa_aUserNotEnrolled_goesToEnrolment_withoutAFullSession() throws Exception {
        when(executor.begin(any(), any())).thenReturn(FlowProgress.completed("bob"));
        when(enrolment.mustEnrol(any(), eq("bob"))).thenReturn(true);
        final MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, passwordAuth("bob"));

        assertThat(response.getRedirectedUrl()).endsWith("/mfa/enable");
        final Authentication now = SecurityContextHolder.getContext().getAuthentication();
        assertThat(now).isInstanceOf(MfaAuthentication.class);
        assertThat(now.isAuthenticated()).isFalse();
    }

    @Test
    void withoutAnMfaRequirement_theFlowCompletesToAFullSession() throws Exception {
        when(executor.begin(any(), any())).thenReturn(FlowProgress.completed("bob"));
        final MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, passwordAuth("bob"));

        assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
        assertThat(response.getRedirectedUrl()).doesNotContain("/mfa/");
    }
}
