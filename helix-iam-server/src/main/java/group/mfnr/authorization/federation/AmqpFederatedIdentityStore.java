package group.mfnr.authorization.federation;

import group.mfnr.authorization.amqp.federation.FederatedIdentityPublisher;
import group.mfnr.authorization.amqp.federation.FederatedLink;
import group.mfnr.authorization.amqp.federation.FederatedLinkLookup;
import group.mfnr.authorization.amqp.federation.FederatedUserProvision;
import group.mfnr.authorization.federation.spi.BrokeredIdentity;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5.3: the production {@link FederatedIdentityStore}. Adapts the broker's pure store seam
 * onto the federation AMQP exchange (the subscriber owns the federated_link table + user domain). A
 * {@code null} answer from the publisher (no link / no user) becomes an empty {@link Optional}.
 */
@Component
public class AmqpFederatedIdentityStore implements FederatedIdentityStore {

    private final FederatedIdentityPublisher publisher;

    public AmqpFederatedIdentityStore(final FederatedIdentityPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public Optional<String> findLinkedUser(final String idpAlias, final String externalSubject) {
        return Optional.ofNullable(publisher.findLinkedUser(new FederatedLinkLookup(idpAlias, externalSubject)));
    }

    @Override
    public Optional<String> findUserByEmail(final String email) {
        return Optional.ofNullable(publisher.findUserByEmail(email));
    }

    @Override
    public void link(final String idpAlias, final String externalSubject, final String userId) {
        publisher.link(new FederatedLink(idpAlias, externalSubject, userId));
    }

    @Override
    public String provisionUser(final BrokeredIdentity identity, final Map<String, String> attributes) {
        return publisher.provisionUser(new FederatedUserProvision(identity.email(), attributes));
    }
}
