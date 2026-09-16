package group.mfnr.authorization.amqp.credential.adapter;

import group.mfnr.authorization.amqp.credential.CredentialPublisher;
import group.mfnr.authorization.amqp.credential.CredentialVerification;
import group.mfnr.authorization.service.credential.CredentialProviderRegistry;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link CredentialPublisher}.
 */
@Component
public class CredentialLocalAdapter implements CredentialPublisher {

    private final CredentialProviderRegistry registry;

    public CredentialLocalAdapter(final CredentialProviderRegistry registry) {
        this.registry = registry;
    }

    @Override
    public Boolean verify(final CredentialVerification verification) {
        return registry.verify(verification.getType(), verification.getUserId(), verification.getInput());
    }
}
