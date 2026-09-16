package io.helixiam.authorization.amqp.federation.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.federation.IdentityProviderConfigService;
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
                bridge.to(config, io.helixiam.authorization.domain.federation.IdentityProviderConfig.class)),
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
