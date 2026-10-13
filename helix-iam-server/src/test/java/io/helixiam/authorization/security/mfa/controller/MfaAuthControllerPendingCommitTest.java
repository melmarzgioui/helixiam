/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.mfa.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.federation.FederatedLoginCommit;
import io.helixiam.authorization.flow.FlowExecutionState;
import io.helixiam.authorization.security.flow.FlowLoginSuccessHandler;
import io.helixiam.authorization.security.mfa.totp.QrCode;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.security.realm.RealmSettingsResolver;
import io.helixiam.authorization.security.realm.SessionPolicyApplier;
import io.helixiam.authorization.service.MfaService;
import io.helixiam.authorization.service.mfa.MfaPolicyService;
import io.helixiam.authorization.service.mfa.TotpService;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.ExtendedModelMap;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Production readiness item 6: a federated login that had to enrol in MFA first ({@code /mfa/enable}) makes its pending
 * commit when the enrolment completes. When that commit is refused, the login has ended: the user sees the federation
 * error, never the recovery-codes page with a "continue" that leads to {@code /login?error=federation}, and no recovery
 * codes are issued for a sign-in that did not happen.
 */
class MfaAuthControllerPendingCommitTest {

    private static final String SP = "https://helix.test";

    private final MfaService mfaService = mock(MfaService.class);
    private final TotpService totp = mock(TotpService.class);
    private final MfaRecoveryPublisher recoveryCodes = mock(MfaRecoveryPublisher.class);
    private final FederatedLoginCommit commit = mock(FederatedLoginCommit.class);
    private final MfaAuthController controller = new MfaAuthController(mock(QrCode.class), mfaService, totp,
            mock(MfaPolicyService.class), recoveryCodes, SP,
            new SessionPolicyApplier(mock(RealmSettingsResolver.class)));

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
        SecurityContextHolder.clearContext();
    }

    private static UserCredentials user() throws Exception {
        return new ObjectMapper().readValue("{\"userId\":\"user-9\",\"username\":\"user-9\",\"mfaEnabled\":false,"
                + "\"authorities\":[{\"role\":\"ROLE_USER\"}]}", UserCredentials.class);
    }

    /** user-9 confirms a TOTP enrolment while a federated login of theirs waits with a pending commit. */
    private MockHttpServletRequest enrolling() {
        controller.setLoginCommits(List.of(commit));
        when(commit.supports("pending-link")).thenReturn(true);
        when(totp.isEnrolled("user-9")).thenReturn(false);
        when(totp.confirmEnrolment("user-9", "SECRET", "123456")).thenReturn(true);
        when(recoveryCodes.generate("user-9")).thenReturn(new ArrayList<>(List.of("code-1", "code-2")));
        RealmContextHolder.set("master");
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final HttpSession session = request.getSession(true);
        session.setAttribute(MfaAuthController.PENDING_SECRET, "SECRET");
        final FlowExecutionState state = new FlowExecutionState("master");
        state.setUserId("user-9");
        state.setPendingCommit("pending-link");
        session.setAttribute(FlowLoginSuccessHandler.FLOW_STATE_ATTRIBUTE, state);
        return request;
    }

    @Test
    void anAcceptedCommit_showsTheRecoveryCodes_andContinuesTheSignIn() throws Exception {
        final MockHttpServletRequest request = enrolling();
        when(commit.commit("pending-link", "user-9")).thenReturn(true);
        final ExtendedModelMap model = new ExtendedModelMap();

        final String view = controller.processEnableMfaFactor("123456", user(), model, request,
                new MockHttpServletResponse());

        assertThat(view).isEqualTo("mfa/recovery-codes");
        assertThat(model.get("recoveryCodes")).isEqualTo(List.of("code-1", "code-2"));
        assertThat(model.get("continueUrl")).isEqualTo(SP);
    }

    @Test
    void aRefusedCommit_showsTheFederationError_notTheRecoveryCodesPage() throws Exception {
        final MockHttpServletRequest request = enrolling();
        when(commit.commit("pending-link", "user-9")).thenReturn(false);
        final ExtendedModelMap model = new ExtendedModelMap();

        final String view = controller.processEnableMfaFactor("123456", user(), model, request,
                new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        assertThat(model.containsAttribute("recoveryCodes")).isFalse();
        verify(recoveryCodes, never()).generate(any());
        assertThat(request.getSession(false)).as("the half-signed-in session is gone").isNull();
    }
}
