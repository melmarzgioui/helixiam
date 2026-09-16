package group.mfnr.authorization.federation;

import group.mfnr.authorization.amqp.federation.IdentityProviderConfig;
import group.mfnr.authorization.amqp.federation.IdentityProviderConfigPublisher;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Helix IAM E8.3: loads persisted identity-provider configs from the identity-domain store over AMQP
 * (the E8.2 publisher), so the federation registry can refresh from the DB the admin console writes to.
 */
@Component
public class AmqpIdentityProviderConfigSource implements IdentityProviderConfigSource {

    private final IdentityProviderConfigPublisher publisher;

    public AmqpIdentityProviderConfigSource(final IdentityProviderConfigPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public List<IdentityProviderConfig> load(final String realmId) {
        return publisher.list(realmId);
    }
}
