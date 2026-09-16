package io.helixiam.authorization.amqp.federation.adapter;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.amqp.federation.FederatedLink;
import io.helixiam.authorization.amqp.federation.FederatedLinkLookup;
import io.helixiam.authorization.amqp.federation.FederatedUserProvision;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.domain.UserCredentials;
import io.helixiam.authorization.service.federation.FederatedIdentityService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link FederatedIdentityPublisher}.
 */
@Component
public class FederatedIdentityLocalAdapter implements FederatedIdentityPublisher {

    private final FederatedIdentityService federatedIdentityService;
    private final DtoBridge bridge;

    public FederatedIdentityLocalAdapter(final FederatedIdentityService federatedIdentityService,
                                         final DtoBridge bridge) {
        this.federatedIdentityService = federatedIdentityService;
        this.bridge = bridge;
    }

    @Override
    public String findLinkedUser(final FederatedLinkLookup lookup) {
        return federatedIdentityService.findLinkedUser(lookup.idpAlias(), lookup.externalSubject()).orElse(null);
    }

    @Override
    public String findUserByEmail(final String email) {
        return federatedIdentityService.findUserByEmail(email).orElse(null);
    }

    @Override
    public Boolean link(final FederatedLink link) {
        federatedIdentityService.link(link.idpAlias(), link.externalSubject(), link.userId());
        return Boolean.TRUE;
    }

    @Override
    public String provisionUser(final FederatedUserProvision provision) {
        return federatedIdentityService.provisionUser(provision.email(), provision.attributes());
    }

    @Override
    public UserCredentials loadUser(final String userId) {
        return bridge.to(federatedIdentityService.loadUser(userId), UserCredentials.class);
    }
}
