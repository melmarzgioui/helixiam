/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Security (MFA gate): in the authorization-server chain the filter runs before the session's SecurityContext is
 * loaded into the holder. It must still see the session's sign-in and gate it, without leaving a context on the thread.
 */
class MfaEnforcementFilterTest {

    private final MfaPolicyService policy = mock(MfaPolicyService.class);
    private final TotpService totp = mock(TotpService.class);
    private final MfaEnforcementFilter filter = new MfaEnforcementFilter(policy, totp, new InMemoryRegisteredClientRepository(
            RegisteredClient.withId("1").clientId("web").clientSecret("{noop}s")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("https://app.example/cb").scope("openid").build()));

    @BeforeEach
    void setUp() {
        RealmContextHolder.set("mf");
        when(policy.required("mf")).thenReturn(true);
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    private static Authentication signedIn(final String userId) {
        final UserCredentials user = mock(UserCredentials.class);
        when(user.getUsername()).thenReturn(userId);
        return UsernamePasswordAuthenticationToken.authenticated(user, null, List.of());
    }

    private static MockHttpServletRequest authorize(final MockHttpSession session) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/realms/mf/oauth2/authorize");
        request.setContextPath("/realms/mf");
        request.setServletPath("/oauth2/authorize");
        request.setParameter("client_id", "web");
        request.setParameter("redirect_uri", "https://app.example/cb");
        request.setParameter("state", "s1");
        request.setSession(session);
        return request;
    }

    private static MockHttpSession sessionWith(final Authentication auth) {
        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(MfaEnforcementFilter.SPRING_SECURITY_CONTEXT_KEY, new SecurityContextImpl(auth));
        return session;
    }

    @Test
    void aSessionSignInNotYetInTheHolder_isGated_andTheHolderIsLeftEmpty() throws Exception {
        final MockHttpSession session = sessionWith(signedIn("u1"));
        final MockHttpServletResponse response = new MockHttpServletResponse();
        final MockFilterChain chain = new MockFilterChain();

        filter.doFilter(authorize(session), response, chain);

        assertThat(chain.getRequest()).as("the authorization endpoint is not reached").isNull();
        assertThat(response.getRedirectedUrl()).isEqualTo("/realms/mf/mfa/enable");
        assertThat(((SecurityContext) session.getAttribute(MfaEnforcementFilter.SPRING_SECURITY_CONTEXT_KEY))
                .getAuthentication()).isInstanceOf(MfaAuthentication.class);
        assertThat(session.getAttribute("SPRING_SECURITY_SAVED_REQUEST")).as("resumed after the second step").isNotNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).as("no context left on the thread").isNull();
    }

    @Test
    void anEnrolledUser_goesToTheCodePage() throws Exception {
        when(totp.isEnrolled("u1")).thenReturn(true);
        when(policy.required("mf")).thenReturn(false);
        final MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(authorize(sessionWith(signedIn("u1"))), response, new MockFilterChain());
        assertThat(response.getRedirectedUrl()).isEqualTo("/realms/mf/mfa/totp");
    }

    @Test
    void aSecondFactorPassedInThisSignIn_orNoRequirement_passes() throws Exception {
        final MockHttpSession session = sessionWith(signedIn("u1"));
        final MockHttpServletRequest request = authorize(session);
        MfaSessionState.markVerified(request, "u1");
        final MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).isNotNull();

        when(policy.required("mf")).thenReturn(false);
        final MockFilterChain other = new MockFilterChain();
        filter.doFilter(authorize(sessionWith(signedIn("u2"))), new MockHttpServletResponse(), other);
        assertThat(other.getRequest()).isNotNull();
    }

    @Test
    void theHolder_isStillUsedWhenPopulated_andGetsTheGatedContext() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(signedIn("u1"));
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(authorize(session), response, new MockFilterChain());
        assertThat(response.getRedirectedUrl()).isEqualTo("/realms/mf/mfa/enable");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isInstanceOf(MfaAuthentication.class);
    }

    @Test
    void promptNone_answersInteractionRequired_atTheRegisteredRedirectUri() throws Exception {
        final MockHttpServletRequest request = authorize(sessionWith(signedIn("u1")));
        request.setParameter("prompt", "none");
        final MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        assertThat(response.getRedirectedUrl()).startsWith("https://app.example/cb?error=interaction_required")
                .contains("state=s1");

        final MockHttpServletRequest foreign = authorize(sessionWith(signedIn("u1")));
        foreign.setParameter("prompt", "none");
        foreign.setParameter("redirect_uri", "https://evil.example/cb");
        final MockHttpServletResponse gated = new MockHttpServletResponse();
        filter.doFilter(foreign, gated, new MockFilterChain());
        assertThat(gated.getRedirectedUrl()).as("never to an unregistered URI").isEqualTo("/realms/mf/mfa/enable");
    }

    @Test
    void anAlreadyGatedOrAnonymousSession_isLeftToTheChain() throws Exception {
        final MockFilterChain chain = new MockFilterChain();
        filter.doFilter(authorize(sessionWith(new MfaAuthentication(signedIn("u1")))), new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).isNotNull();
        final MockFilterChain anonymous = new MockFilterChain();
        filter.doFilter(authorize(new MockHttpSession()), new MockHttpServletResponse(), anonymous);
        assertThat(anonymous.getRequest()).isNotNull();
    }
}
