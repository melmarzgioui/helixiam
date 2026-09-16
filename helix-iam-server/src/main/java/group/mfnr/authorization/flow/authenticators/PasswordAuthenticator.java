package group.mfnr.authorization.flow.authenticators;

import group.mfnr.authorization.flow.spi.AuthenticationContext;
import group.mfnr.authorization.flow.spi.Authenticator;
import group.mfnr.authorization.flow.spi.AuthenticatorMetadata;
import group.mfnr.authorization.flow.spi.FactorClass;

import java.util.Optional;

/**
 * Helix IAM E2.3: username/password authenticator — the identity-establishing first factor.
 * Challenges for credentials, verifies them via {@link PasswordVerifier}, and on success
 * records the resolved user on the context so later steps (OTP, etc.) act on a known user.
 */
public class PasswordAuthenticator implements Authenticator {

    static final String VIEW = "login-form";
    static final String USERNAME_PARAM = "username";
    static final String PASSWORD_PARAM = "password";

    private final PasswordVerifier verifier;

    public PasswordAuthenticator(final PasswordVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.of("password", "Password", FactorClass.KNOWLEDGE, 1);
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        context.challenge(VIEW);
    }

    @Override
    public void action(final AuthenticationContext context) {
        final String username = context.formParameter(USERNAME_PARAM);
        final String password = context.formParameter(PASSWORD_PARAM);
        if (username == null || password == null) {
            context.failure("Missing credentials");
            return;
        }
        final Optional<String> userId = verifier.verify(username, password);
        if (userId.isPresent()) {
            context.establishUser(userId.get());
            context.success();
        } else {
            context.failure("Invalid username or password");
        }
    }
}
