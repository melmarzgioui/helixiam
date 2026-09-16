package group.mfnr.authorization.security.flow;

import group.mfnr.authorization.amqp.credential.CredentialPublisher;
import group.mfnr.authorization.amqp.credential.CredentialVerification;
import group.mfnr.authorization.flow.authenticators.CredentialVerifier;
import org.springframework.stereotype.Component;

/**
 * Helix IAM: live {@link CredentialVerifier} that routes a verification to the subscriber's
 * auto-discovered credential provider for the type over AMQP. Shared by every credential-backed
 * factor (HOTP, recovery-code, …).
 */
@Component
public class AmqpCredentialVerifier implements CredentialVerifier {

    private final CredentialPublisher publisher;

    public AmqpCredentialVerifier(final CredentialPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public boolean verify(final String type, final String userId, final String input) {
        return Boolean.TRUE.equals(publisher.verify(new CredentialVerification(type, userId, input)));
    }
}
