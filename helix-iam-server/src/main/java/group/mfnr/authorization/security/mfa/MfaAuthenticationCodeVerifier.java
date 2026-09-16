package group.mfnr.authorization.security.mfa;

import group.mfnr.authorization.domain.UserCredentials;

public interface MfaAuthenticationCodeVerifier {
    boolean verify(final UserCredentials userCredentials, final String code);
}
