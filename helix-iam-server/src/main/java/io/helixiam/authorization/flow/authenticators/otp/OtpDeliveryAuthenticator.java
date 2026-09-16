/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators.otp;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;

import java.security.SecureRandom;
import java.util.function.LongSupplier;

/**
 * Helix IAM E3.1: shared base for the delivered one-time-code factors (SMS, Email). Issues a
 * 6-digit code, stashes the (hashed) {@link OtpChallenge} in the per-execution state, sends the
 * code via {@link OtpSender}, and verifies the user's response. Subclasses only supply their
 * id and display name.
 */
public abstract class OtpDeliveryAuthenticator implements Authenticator {

    static final String VIEW = "otp-form";
    static final String CODE_PARAM = "code";
    static final String CHALLENGE_ATTRIBUTE = "otp.challenge";

    private static final int CODE_DIGITS = 6;
    private static final long TTL_MS = 300_000L;     // 5 minutes
    private static final int MAX_ATTEMPTS = 3;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OtpSender sender;
    private final LongSupplier clock;

    protected OtpDeliveryAuthenticator(final OtpSender sender, final LongSupplier clock) {
        this.sender = sender;
        this.clock = clock;
    }

    protected abstract String id();

    protected abstract String displayName();

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of(id(), displayName(), FactorClass.POSSESSION, 2);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final String code = generateCode();
        context.putAttribute(CHALLENGE_ATTRIBUTE,
                OtpChallenge.issue(code, TTL_MS, MAX_ATTEMPTS, clock.getAsLong()));
        sender.send(context.userId(), code);
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final Object stashed = context.getAttribute(CHALLENGE_ATTRIBUTE);
        final String submitted = context.formParameter(CODE_PARAM);
        if (stashed instanceof OtpChallenge challenge && submitted != null
                && challenge.verify(submitted, clock.getAsLong())) {
            context.success();
        } else {
            context.failure("Invalid or expired code");
        }
    }

    private String generateCode() {
        final StringBuilder code = new StringBuilder(CODE_DIGITS);
        for (int i = 0; i < CODE_DIGITS; i++) {
            code.append(RANDOM.nextInt(10));
        }
        return code.toString();
    }
}
