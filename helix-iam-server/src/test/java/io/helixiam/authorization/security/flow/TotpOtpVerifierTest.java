/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.security.mfa.MfaAuthenticationCodeVerifier;
import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The flow's TOTP step verifies the code of the user the flow is for, never of another principal in the session. */
class TotpOtpVerifierTest {

    private final MfaAuthenticationCodeVerifier delegate = mock(MfaAuthenticationCodeVerifier.class);
    private final TotpOtpVerifier verifier = new TotpOtpVerifier(delegate);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static void signedInAs(final UserCredentials principal) {
        SecurityContextHolder.getContext().setAuthentication(new MfaAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, principal.getAuthorities())));
    }

    @Test
    void verifiesTheFlowsUser() throws Exception {
        signedInAs(MfaEnabledConditionTest.user("ada", true));
        when(delegate.verify(any(UserCredentials.class), anyString())).thenReturn(true);

        assertThat(verifier.verify("ada", "123456")).isTrue();
    }

    @Test
    void aPrincipalOfAnotherUser_isNotVerifiedInItsPlace() throws Exception {
        signedInAs(MfaEnabledConditionTest.user("bob", true));
        when(delegate.verify(any(UserCredentials.class), anyString())).thenReturn(true);

        assertThat(verifier.verify("ada", "123456")).isFalse();
    }

    @Test
    void withoutAPrincipal_nothingIsVerified() {
        when(delegate.verify(any(UserCredentials.class), anyString())).thenReturn(true);

        assertThat(verifier.verify("ada", "123456")).isFalse();
    }
}
