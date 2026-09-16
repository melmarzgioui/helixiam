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
 * Helix IAM E3.4: HMAC-based (counter) one-time-password factor. Verifies the submitted code via
 * the generic {@link CredentialVerifier} for credential type {@code "hotp"} (the subscriber's
 * HOTP provider advances the counter).
 */
public class HotpAuthenticator implements Authenticator {

    static final String VIEW = "otp-form";
    static final String CODE_PARAM = "code";
    static final String CREDENTIAL_TYPE = "hotp";

    private final CredentialVerifier verifier;

    public HotpAuthenticator(final CredentialVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("hotp", "One-Time Password (HOTP)", FactorClass.POSSESSION, 2);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final String code = context.formParameter(CODE_PARAM);
        if (code != null && verifier.verify(CREDENTIAL_TYPE, context.userId(), code)) {
            context.success();
        } else {
            context.failure("Invalid authentication code");
        }
    }
}
