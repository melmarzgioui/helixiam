package io.helixiam.authorization.service.credential;

import io.helixiam.authorization.service.mfa.RecoveryCodeService;
import org.springframework.stereotype.Component;

/** Helix IAM E3.2/E3.4: recovery codes exposed as an auto-discovered {@link CredentialProvider}. */
@Component
public class RecoveryCodeCredentialProvider implements CredentialProvider {

    private final RecoveryCodeService recoveryCodeService;

    public RecoveryCodeCredentialProvider(final RecoveryCodeService recoveryCodeService) {
        this.recoveryCodeService = recoveryCodeService;
    }

    @Override
    public String type() {
        return "recovery-code";
    }

    @Override
    public boolean verify(final String userId, final String input) {
        return recoveryCodeService.verifyAndConsume(userId, input);
    }
}
