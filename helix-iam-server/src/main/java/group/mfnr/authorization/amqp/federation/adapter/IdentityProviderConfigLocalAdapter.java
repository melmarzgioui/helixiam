package group.mfnr.authorization.amqp.federation.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.federation.IdentityProviderConfig;
import group.mfnr.authorization.amqp.federation.IdentityProviderConfigPublisher;
import group.mfnr.authorization.amqp.federation.IdentityProviderRef;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.federation.IdentityProviderConfigService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link IdentityProviderConfigPublisher}.
 */
@Component
public class IdentityProviderConfigLocalAdapter implements IdentityProviderConfigPublisher {

    private final IdentityProviderConfigService service;
    private final DtoBridge bridge;

    public IdentityProviderConfigLocalAdapter(final IdentityProviderConfigService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public IdentityProviderConfig save(final IdentityProviderConfig config) {
        return bridge.to(service.saveOrUpdate(
                bridge.to(config, group.mfnr.authorization.domain.federation.IdentityProviderConfig.class)),
                IdentityProviderConfig.class);
    }

    @Override
    public List<IdentityProviderConfig> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<IdentityProviderConfig>>() { });
    }

    @Override
    public IdentityProviderConfig get(final IdentityProviderRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.alias()).orElse(null), IdentityProviderConfig.class);
    }

    @Override
    public Boolean delete(final IdentityProviderRef ref) {
        return service.delete(ref.realmId(), ref.alias());
    }
}
