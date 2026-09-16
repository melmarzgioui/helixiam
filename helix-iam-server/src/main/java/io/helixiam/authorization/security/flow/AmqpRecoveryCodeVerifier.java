/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.amqp.mfa.RecoveryCodeVerification;
import io.helixiam.authorization.flow.authenticators.recovery.RecoveryCodeVerifier;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E3.2: live {@link RecoveryCodeVerifier} that verifies-and-burns the code in the
 * subscriber's store over AMQP.
 */
@Component
public class AmqpRecoveryCodeVerifier implements RecoveryCodeVerifier {

    private final MfaRecoveryPublisher publisher;

    public AmqpRecoveryCodeVerifier(final MfaRecoveryPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public boolean verifyAndConsume(final String userId, final String code) {
        return Boolean.TRUE.equals(publisher.verifyAndConsume(new RecoveryCodeVerification(userId, code)));
    }
}
