package group.mfnr.authorization.flow.authenticators.recovery;

/**
 * Helix IAM E3.2: verifies and consumes a single-use recovery code. Keeps
 * {@link RecoveryCodeAuthenticator} decoupled from the store; the live adapter checks the code
 * against the user's hashed codes in the subscriber and burns it on success (over AMQP).
 */
@FunctionalInterface
public interface RecoveryCodeVerifier {

    /** True if the code is valid and unused; consumes it as a side effect. */
    boolean verifyAndConsume(String userId, String code);
}
