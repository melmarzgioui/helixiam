package io.helixiam.authorization.flow.authenticators.recovery;

import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.flow.spi.Authenticator;
import io.helixiam.authorization.flow.spi.AuthenticatorMetadata;
import io.helixiam.authorization.flow.spi.FactorClass;

/**
 * Helix IAM E3.2: recovery-code (backup code) factor. The user enters one of the single-use codes
 * they saved at enrollment; it is verified and burned via {@link RecoveryCodeVerifier}.
 */
public class RecoveryCodeAuthenticator implements Authenticator {

    static final String VIEW = "recovery-code-form";
    static final String CODE_PARAM = "code";

    private final RecoveryCodeVerifier verifier;

    public RecoveryCodeAuthenticator(final RecoveryCodeVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("recovery-code", "Recovery Code", FactorClass.POSSESSION, 1);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final String code = context.formParameter(CODE_PARAM);
        if (code != null && verifier.verifyAndConsume(context.userId(), code)) {
            context.success();
        } else {
            context.failure("Invalid or already-used recovery code");
        }
    }
}
