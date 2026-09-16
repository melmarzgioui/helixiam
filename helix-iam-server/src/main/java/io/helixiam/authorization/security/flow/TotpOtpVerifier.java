package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.flow.authenticators.OtpVerifier;
import io.helixiam.authorization.security.mfa.MfaAuthenticationCodeVerifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Helix IAM E2.4: live {@link OtpVerifier} adapter — bridges the SPI OTP authenticator to the
 * existing TOTP verifier. The user's secret lives on the {@link UserCredentials} principal held
 * (pending MFA) in the security context, so we read it from there, exactly as the legacy
 * {@code MfaAuthController} does via {@code @AuthenticationPrincipal}.
 */
@Component
public class TotpOtpVerifier implements OtpVerifier {

    private final MfaAuthenticationCodeVerifier delegate;

    public TotpOtpVerifier(final MfaAuthenticationCodeVerifier delegate) {
        this.delegate = delegate;
    }

    @Override
    public boolean verify(final String userId, final String code) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        final Object principal = authentication == null ? null : authentication.getPrincipal();
        if (principal instanceof UserCredentials userCredentials) {
            return delegate.verify(userCredentials, code);
        }
        return false;
    }
}
