package io.helixiam.authorization.amqp.mfa.adapter;

import io.helixiam.authorization.amqp.mfa.MfaRecoveryPublisher;
import io.helixiam.authorization.amqp.mfa.RecoveryCodeVerification;
import io.helixiam.authorization.service.mfa.RecoveryCodeService;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link MfaRecoveryPublisher}.
 */
@Component
public class MfaRecoveryLocalAdapter implements MfaRecoveryPublisher {

    private static final int DEFAULT_CODE_COUNT = 10;

    private final RecoveryCodeService recoveryCodeService;

    public MfaRecoveryLocalAdapter(final RecoveryCodeService recoveryCodeService) {
        this.recoveryCodeService = recoveryCodeService;
    }

    @Override
    public Boolean verifyAndConsume(final RecoveryCodeVerification verification) {
        return recoveryCodeService.verifyAndConsume(verification.getUserId(), verification.getCode());
    }

    @Override
    public ArrayList<String> generate(final String userId) {
        return new ArrayList<>(recoveryCodeService.generate(userId, DEFAULT_CODE_COUNT));
    }
}
