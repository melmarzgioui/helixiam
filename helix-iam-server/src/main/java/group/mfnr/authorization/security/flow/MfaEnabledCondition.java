package group.mfnr.authorization.security.flow;

import group.mfnr.authorization.domain.UserCredentials;
import group.mfnr.authorization.flow.spi.AuthenticationContext;
import group.mfnr.authorization.flow.spi.Authenticator;
import group.mfnr.authorization.flow.spi.AuthenticatorMetadata;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E2.5: a flow condition that passes when the current user has MFA enabled. It gates a
 * CONDITIONAL step-up sub-flow, replacing the old in-code {@code if (mfaEnabled)} branch with a
 * data-driven condition the admin console can rewire. Reads the user from the (MFA-pending)
 * principal in the security context, like {@link TotpOtpVerifier}.
 */
@Component
public class MfaEnabledCondition implements Authenticator {

    public static final String ID = "mfa-enabled";

    @Override
    public AuthenticatorMetadata metadata() {
        return AuthenticatorMetadata.condition(ID, "User has MFA enabled");
    }

    @Override
    public void authenticate(final AuthenticationContext context) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        final Object principal = authentication == null ? null : authentication.getPrincipal();
        if (principal instanceof UserCredentials userCredentials && userCredentials.isMfaEnabled()) {
            context.success();
        } else {
            context.failure("MFA not enabled");
        }
    }
}
