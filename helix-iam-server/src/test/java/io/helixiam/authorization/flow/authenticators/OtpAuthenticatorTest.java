/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E2.3: the OTP authenticator prompts for a code, then verifies the submitted code
 * against the user's enrolled secret via an injected {@link OtpVerifier}.
 */
class OtpAuthenticatorTest {

    private AuthenticationContext context() {
        return new AuthenticationContext("e-otp", "master", "user-1");
    }

    @Test
    void metadata_isAPossessionFactorWithIdOtp() {
        OtpAuthenticator authenticator = new OtpAuthenticator((userId, code) -> true);

        assertThat(authenticator.metadata().id()).isEqualTo("otp");
        assertThat(authenticator.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_promptsForTheCode() {
        OtpAuthenticator authenticator = new OtpAuthenticator((userId, code) -> true);
        AuthenticationContext ctx = context();

        authenticator.authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("otp-form");
    }

    @Test
    void action_validCode_succeeds() {
        OtpAuthenticator authenticator =
                new OtpAuthenticator((userId, code) -> userId.equals("user-1") && code.equals("123456"));
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("code", "123456"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void action_invalidCode_fails() {
        OtpAuthenticator authenticator = new OtpAuthenticator((userId, code) -> false);
        AuthenticationContext ctx = context();
        ctx.submit(Map.of("code", "000000"));

        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void action_missingCode_fails() {
        OtpAuthenticator authenticator = new OtpAuthenticator((userId, code) -> true);
        AuthenticationContext ctx = context();

        authenticator.action(ctx); // nothing submitted

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
