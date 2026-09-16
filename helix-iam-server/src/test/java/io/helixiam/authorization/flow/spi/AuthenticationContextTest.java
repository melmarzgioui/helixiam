/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.spi;

import io.helixiam.authorization.flow.ExecutionOutcome;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.1: the context an {@link Authenticator} drives during one execution. Its
 * terminal status maps to the engine's {@link ExecutionOutcome}; a CHALLENGE is not yet an
 * outcome (the user still has to respond).
 */
class AuthenticationContextTest {

    private AuthenticationContext newContext() {
        return new AuthenticationContext("e-otp", "master", "user-1");
    }

    @Test
    void newContext_isAttempting_withNoOutcomeYet() {
        AuthenticationContext ctx = newContext();

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.ATTEMPTING);
        assertThat(ctx.outcome()).isEmpty();
    }

    @Test
    void success_yieldsSucceededOutcome() {
        AuthenticationContext ctx = newContext();

        ctx.success();

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(ctx.outcome()).contains(ExecutionOutcome.SUCCEEDED);
    }

    @Test
    void failure_yieldsFailedOutcome_withMessage() {
        AuthenticationContext ctx = newContext();

        ctx.failure("invalid code");

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(ctx.outcome()).contains(ExecutionOutcome.FAILED);
        assertThat(ctx.message()).isEqualTo("invalid code");
    }

    @Test
    void challenge_holdsTheView_andHasNoOutcomeYet() {
        AuthenticationContext ctx = newContext();

        ctx.challenge("otp-form");

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("otp-form");
        assertThat(ctx.outcome()).isEmpty();
    }

    @Test
    void exposesItsExecutionRealmAndUser() {
        AuthenticationContext ctx = newContext();

        assertThat(ctx.executionId()).isEqualTo("e-otp");
        assertThat(ctx.realmId()).isEqualTo("master");
        assertThat(ctx.userId()).isEqualTo("user-1");
    }

    @Test
    void userIsEstablishedByAnIdentityStep_whenInitiallyUnknown() {
        AuthenticationContext ctx = new AuthenticationContext("e-pass", "master", null);
        assertThat(ctx.userId()).isNull();

        ctx.establishUser("user-1");

        assertThat(ctx.userId()).isEqualTo("user-1");
    }

    @Test
    void submittedFormParameters_areReadableByTheAuthenticator() {
        AuthenticationContext ctx = newContext();

        ctx.submit(java.util.Map.of("code", "123456"));

        assertThat(ctx.formParameter("code")).isEqualTo("123456");
        assertThat(ctx.formParameter("missing")).isNull();
    }
}
