package io.helixiam.authorization.amqp.credential.adapter;

import io.helixiam.authorization.amqp.credential.CredentialPublisher;
import io.helixiam.authorization.amqp.credential.CredentialVerification;
import io.helixiam.authorization.service.credential.CredentialProviderRegistry;
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
