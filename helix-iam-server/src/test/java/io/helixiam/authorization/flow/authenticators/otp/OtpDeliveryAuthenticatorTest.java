/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators.otp;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.FactorClass;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E3.1: the delivered one-time-code factors (SMS, Email). They issue a code, send it
 * via the {@link OtpSender} seam, and verify the user's response — sharing all logic but
 * differing only in id/factor and channel.
 */
class OtpDeliveryAuthenticatorTest {

    private final AtomicReference<String> sentCode = new AtomicReference<>();
    private final AtomicReference<String> sentTo = new AtomicReference<>();
    private final OtpSender capturingSender = (userId, code) -> {
        sentTo.set(userId);
        sentCode.set(code);
    };

    private AuthenticationContext context() {
        return new AuthenticationContext("e-sms", "master", "user-1");
    }

    private SmsOtpAuthenticator sms() {
        return new SmsOtpAuthenticator(capturingSender, () -> 1_000_000L);
    }

    @Test
    void smsMetadata_isPossessionFactor() {
        assertThat(sms().metadata().id()).isEqualTo("sms-otp");
        assertThat(sms().metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void emailMetadata_isPossessionFactorWithItsOwnId() {
        EmailOtpAuthenticator email = new EmailOtpAuthenticator(capturingSender, () -> 1_000_000L);
        assertThat(email.metadata().id()).isEqualTo("email-otp");
        assertThat(email.metadata().factorClass()).isEqualTo(FactorClass.POSSESSION);
    }

    @Test
    void authenticate_sendsACodeToTheUser_andChallenges() {
        AuthenticationContext ctx = context();

        sms().authenticate(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(ctx.challengeView()).isEqualTo("otp-form");
        assertThat(sentTo.get()).isEqualTo("user-1");
        assertThat(sentCode.get()).hasSize(6).containsOnlyDigits();
    }

    @Test
    void action_withTheSentCode_succeeds() {
        SmsOtpAuthenticator authenticator = sms();
        AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);

        ctx.submit(Map.of("code", sentCode.get()));
        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void action_withAWrongCode_fails() {
        SmsOtpAuthenticator authenticator = sms();
        AuthenticationContext ctx = context();
        authenticator.authenticate(ctx);

        ctx.submit(Map.of("code", "000000"));
        authenticator.action(ctx);

        assertThat(ctx.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }
}
