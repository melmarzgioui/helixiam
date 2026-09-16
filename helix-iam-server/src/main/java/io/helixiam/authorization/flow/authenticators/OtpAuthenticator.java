/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.flow.authenticators;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;

/**
 * Helix IAM E2.3: time-based one-time-password authenticator (the existing TOTP factor, now
 * an SPI plug-in). Challenges for a code, then verifies it via {@link OtpVerifier}.
 */
public class OtpAuthenticator implements Authenticator {

    static final String VIEW = "otp-form";
    static final String CODE_PARAM = "code";

    private final OtpVerifier verifier;

    public OtpAuthenticator(final OtpVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("otp", "One-Time Password (TOTP)", FactorClass.POSSESSION, 2);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final String code = context.formParameter(CODE_PARAM);
        if (code != null && verifier.verify(context.userId(), code)) {
            context.success();
        } else {
            context.failure("Invalid authentication code");
        }
    }
}
