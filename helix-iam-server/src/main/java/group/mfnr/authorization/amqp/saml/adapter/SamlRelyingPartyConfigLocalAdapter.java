package group.mfnr.authorization.amqp.saml.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfig;
import group.mfnr.authorization.amqp.saml.SamlRelyingPartyConfigPublisher;
import group.mfnr.authorization.amqp.saml.SamlRelyingPartyRef;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.saml.SamlRelyingPartyConfigService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link SamlRelyingPartyConfigPublisher}.
 */
@Component
public class SamlRelyingPartyConfigLocalAdapter implements SamlRelyingPartyConfigPublisher {

    private final SamlRelyingPartyConfigService service;
    private final DtoBridge bridge;

    public SamlRelyingPartyConfigLocalAdapter(final SamlRelyingPartyConfigService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public SamlRelyingPartyConfig save(final SamlRelyingPartyConfig config) {
        return bridge.to(service.saveOrUpdate(
                bridge.to(config, group.mfnr.authorization.domain.saml.SamlRelyingPartyConfig.class)),
                SamlRelyingPartyConfig.class);
    }

    @Override
    public List<SamlRelyingPartyConfig> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<SamlRelyingPartyConfig>>() { });
    }

    @Override
    public SamlRelyingPartyConfig get(final SamlRelyingPartyRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.entityId()).orElse(null), SamlRelyingPartyConfig.class);
    }

    @Override
    public Boolean delete(final SamlRelyingPartyRef ref) {
        return service.delete(ref.realmId(), ref.entityId());
    }
}
