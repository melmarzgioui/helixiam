package group.mfnr.authorization.amqp.mfa;


import java.util.ArrayList;

/**
 * Helix IAM E3.2: recovery-code operations against the subscriber (the owner of the codes) over
 * AMQP — verify-and-consume at login, regenerate at enrollment.
 */
public interface MfaRecoveryPublisher {

    String EXCHANGE_AUTHORIZATION_MFA = "exchange-authorization-mfa";
    String RECOVERY_CODE_VERIFY = "authorization.mfa.recovery.verify";
    String RECOVERY_CODE_GENERATE = "authorization.mfa.recovery.generate";

    Boolean verifyAndConsume(final RecoveryCodeVerification verification);

    ArrayList<String> generate(final String userId);
}
