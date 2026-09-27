/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.requiredactions.RequiredActionsGate;
import io.helixiam.authorization.service.emailverification.EmailVerificationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ExtendedModelMap;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * CodeQL #258 ({@code java/csrf-unprotected-request-type}): {@code GET /required-actions} only shows the page. The
 * verification link is emailed by the gate, inside the (CSRF-protected) sign-in {@code POST}; "send again" is its own
 * {@code POST}.
 */
class RequiredActionsVerifyEmailTest {

    private final UserAdminPublisher users = mock(UserAdminPublisher.class);
    private final EmailVerificationService verification = mock(EmailVerificationService.class);

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void theRequiredActionsPage_isAGetWithoutSideEffects_itSendsNoEmail() throws Exception {
        final RequiredActionsController controller = new RequiredActionsController(users, null, null, null, null, null, "/");
        controller.setEmailVerification(verification, "https://idp.example");
        when(verification.emailOf("u-1")).thenReturn(Optional.of("ada@example.com"));
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/required-actions");
        request.getSession().setAttribute(RequiredActionsGate.PENDING_ACTIONS_ATTR, EmailVerificationService.VERIFY_EMAIL);
        request.getSession().setAttribute(RequiredActionsGate.PENDING_REALM_ATTR, "acme");
        request.getSession().setAttribute(RequiredActionsGate.PENDING_AUTH_ATTR, auth("u-1"));

        final ExtendedModelMap model = new ExtendedModelMap();
        final String view = controller.page(request, new MockHttpServletResponse(), model);
        controller.page(request, new MockHttpServletResponse(), new ExtendedModelMap());

        assertThat(view).isEqualTo("required-actions/verify-email");
        assertThat(model.get("email")).isEqualTo("ada@example.com");
        verify(verification, never()).send(any(), any(), any());
    }

    @Test
    void theSignInGate_emailsTheLinkWhenItHoldsTheUserForVerification() throws Exception {
        final RequiredActionsGate gate = new RequiredActionsGate(users, verification, "https://idp.example/");
        RealmContextHolder.set("acme");
        when(users.getRequiredActions("u-1")).thenReturn("");
        when(verification.pending("acme", "u-1")).thenReturn(true);
        final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        final MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(gate.intercept(request, response, auth("u-1"))).isTrue();

        verify(verification).send("acme", "u-1", "https://idp.example/realms/acme");
        assertThat(response.getRedirectedUrl()).isEqualTo("/required-actions");
    }

    @Test
    void theSignInGate_sendsNothingForOtherActions_orWithoutAConfiguredBaseUrl() throws Exception {
        RealmContextHolder.set("acme");
        when(users.getRequiredActions("u-1")).thenReturn("UPDATE_PASSWORD");
        new RequiredActionsGate(users, verification, "https://idp.example")
                .intercept(new MockHttpServletRequest(), new MockHttpServletResponse(), auth("u-1"));

        when(verification.pending("acme", "u-1")).thenReturn(true);
        new RequiredActionsGate(users, verification, "")
                .intercept(new MockHttpServletRequest(), new MockHttpServletResponse(), auth("u-1"));

        verify(verification, never()).send(anyString(), anyString(), anyString());
    }

    private static UsernamePasswordAuthenticationToken auth(final String userId) {
        final UserCredentials user = mock(UserCredentials.class);
        when(user.getUserId()).thenReturn(userId);
        when(user.getUsername()).thenReturn(userId);
        return new UsernamePasswordAuthenticationToken(user, null, List.of());
    }
}
