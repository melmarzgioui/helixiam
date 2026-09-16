package group.mfnr.authorization.amqp.adapter;

import group.mfnr.authorization.amqp.AuthFlowPublisher;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.flow.persistence.AuthFlowDefinition;
import group.mfnr.authorization.service.ServiceProviderService;
import group.mfnr.authorization.service.flow.AuthFlowService;
import group.mfnr.authorization.support.RealmScopedKey;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AuthFlowPublisher}. The domain-side {@code group.mfnr.authorization.domain.flow.AuthFlowDefinition}
 * is bridged to the flow-engine's {@link AuthFlowDefinition} (the two-copy DTO the login exchange used).
 */
@Component
public class AuthFlowLocalAdapter implements AuthFlowPublisher {

    private final AuthFlowService authFlowService;
    private final ServiceProviderService serviceProviderService;
    private final DtoBridge bridge;

    public AuthFlowLocalAdapter(final AuthFlowService authFlowService,
                                final ServiceProviderService serviceProviderService,
                                final DtoBridge bridge) {
        this.authFlowService = authFlowService;
        this.serviceProviderService = serviceProviderService;
        this.bridge = bridge;
    }

    @Override
    public AuthFlowDefinition retrieveBrowserFlow(final String realmId) {
        return bridge.to(authFlowService.getDefinition(realmId, AuthFlowService.BROWSER_FLOW),
                AuthFlowDefinition.class);
    }

    @Override
    public AuthFlowDefinition retrieveFlowForClient(final String realmScopedClientId) {
        final String[] parts = RealmScopedKey.split(realmScopedClientId);
        final String realm = parts[0];
        final String clientId = parts[1];
        final String alias = serviceProviderService.getFlowAlias(clientId, realm);
        return bridge.to(authFlowService.getDefinitionOrBrowser(realm, alias), AuthFlowDefinition.class);
    }
}
