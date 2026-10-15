/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import tools.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The {@code mfa-enabled} flow condition gates the second-factor step. It must answer for the user the flow is for
 * (the flow state's user), not for whoever is in the security context: after a brokered (OIDC / SAML / eID) login
 * the context is still empty when the flow starts, and "no principal" must not read as "MFA not enabled".
 */
class MfaEnabledConditionTest {

    private final FederatedIdentityPublisher users = mock(FederatedIdentityPublisher.class);
    private final MfaEnabledCondition condition = new MfaEnabledCondition(users);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    static UserCredentials user(final String id, final boolean mfaEnabled) throws Exception {
        return new ObjectMapper().readValue("{\"userId\":\"" + id + "\",\"username\":\"" + id + "@corp\",\"mfaEnabled\":"
                + mfaEnabled + ",\"authorities\":[{\"role\":\"ROLE_USER\"}]}", UserCredentials.class);
    }

    private static AuthenticationContext contextFor(final String userId) {
        return new AuthenticationContext("gate", "gov", userId);
    }

    private static void signedInAs(final UserCredentials principal) {
        SecurityContextHolder.getContext().setAuthentication(new MfaAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities())));
    }

    @Test
    void withNoPrincipal_theFlowsMfaUser_isChallenged() throws Exception {
        when(users.loadUser("ada")).thenReturn(user("ada", true));
        final AuthenticationContext context = contextFor("ada");

        condition.authenticate(context);

        assertThat(context.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void withNoPrincipal_aUserWithoutMfa_isNot() throws Exception {
        when(users.loadUser("bob")).thenReturn(user("bob", false));
        final AuthenticationContext context = contextFor("bob");

        condition.authenticate(context);

        assertThat(context.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void thePrincipalOfAnotherUser_doesNotDecide() throws Exception {
        signedInAs(user("bob", false));
        when(users.loadUser("ada")).thenReturn(user("ada", true));
        final AuthenticationContext context = contextFor("ada");

        condition.authenticate(context);

        assertThat(context.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void thePrincipalOfTheFlowsUser_isUsedWithoutALookup() throws Exception {
        signedInAs(user("ada", true));
        final AuthenticationContext context = contextFor("ada");

        condition.authenticate(context);

        assertThat(context.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        verify(users, never()).loadUser("ada");
    }

    @Test
    void aFlowUserThatCannotBeLoaded_failsClosed_ratherThanSkippingTheSecondFactor() {
        when(users.loadUser("ghost")).thenReturn(null);

        assertThatThrownBy(() -> condition.authenticate(contextFor("ghost"))).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void withoutAFlowUser_thePrincipalStillDecides() throws Exception {
        signedInAs(user("ada", true));
        final AuthenticationContext withPrincipal = contextFor(null);
        condition.authenticate(withPrincipal);
        assertThat(withPrincipal.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);

        SecurityContextHolder.clearContext();
        final AuthenticationContext nobody = contextFor(null);
        condition.authenticate(nobody);
        assertThat(nobody.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
