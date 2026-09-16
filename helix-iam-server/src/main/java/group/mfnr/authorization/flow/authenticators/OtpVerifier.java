package group.mfnr.authorization.flow.authenticators;

/**
 * Helix IAM E2.3: verifies a submitted one-time code against a user's enrolled secret. Keeps
 * {@link OtpAuthenticator} decoupled from the concrete TOTP library + user lookup (the live
 * adapter bridges to the existing {@code MfaAuthenticationCodeVerifier}).
 */
@FunctionalInterface
public interface OtpVerifier {
    boolean verify(String userId, String code);
}
