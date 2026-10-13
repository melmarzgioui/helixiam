/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.user.UserPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * {@link MfaService#unlockUser(String)} promotes a pending second-factor sign-in only for exactly the expected user,
 * and fails closed when no user is expected — including against a pending principal that itself has no user id.
 */
class MfaServiceUnlockTest {

    private final MfaService service = new MfaService(mock(UserPublisher.class));

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MfaAuthentication pendingOf(final String userIdJson) throws Exception {
        final UserCredentials user = new ObjectMapper().readValue("{\"userId\":" + userIdJson
                + ",\"username\":\"u@corp\",\"authorities\":[{\"role\":\"ROLE_USER\"}]}", UserCredentials.class);
        final MfaAuthentication pending = new MfaAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(user, null, user.getAuthorities()));
        SecurityContextHolder.getContext().setAuthentication(pending);
        return pending;
    }

    @Test
    void aNullExpectedUser_promotesNothing() throws Exception {
        final MfaAuthentication pending = pendingOf("\"ada\"");

        assertThat(service.unlockUser(null)).isFalse();
        assertThat(service.isPendingSignInOf(null)).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(pending);
    }

    @Test
    void aNullExpectedUser_doesNotMatchAPendingPrincipalWithoutAnId() throws Exception {
        final MfaAuthentication pending = pendingOf("null");

        assertThat(service.unlockUser(null)).isFalse();
        assertThat(service.isPendingSignInOf(null)).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(pending);
    }

    @Test
    void anotherUser_isNotPromoted() throws Exception {
        final MfaAuthentication pending = pendingOf("\"bob\"");

        assertThat(service.unlockUser("ada")).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(pending);
    }

    @Test
    void theExpectedUser_isPromotedToTheFullAuthentication() throws Exception {
        final MfaAuthentication pending = pendingOf("\"ada\"");

        assertThat(service.isPendingSignInOf("ada")).isTrue();
        assertThat(service.unlockUser("ada")).isTrue();
        final Authentication now = SecurityContextHolder.getContext().getAuthentication();
        assertThat(now).isSameAs(pending.getOriginalUserObject());
        assertThat(now.isAuthenticated()).isTrue();
    }

    @Test
    void noPendingSignIn_promotesNothing() {
        assertThat(service.unlockUser("ada")).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
