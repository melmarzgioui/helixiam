package group.mfnr.authorization.amqp.application.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.application.ApplicationConfig;
import group.mfnr.authorization.amqp.application.ApplicationConfigPublisher;
import group.mfnr.authorization.amqp.application.ApplicationRef;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.application.ApplicationConfigService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ApplicationConfigPublisher}.
 */
@Component
public class ApplicationConfigLocalAdapter implements ApplicationConfigPublisher {

    private final ApplicationConfigService service;
    private final DtoBridge bridge;

    public ApplicationConfigLocalAdapter(final ApplicationConfigService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public ApplicationConfig save(final ApplicationConfig config) {
        return bridge.to(service.saveOrUpdate(
                bridge.to(config, group.mfnr.authorization.domain.application.ApplicationConfig.class)),
                ApplicationConfig.class);
    }

    @Override
    public List<ApplicationConfig> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<ApplicationConfig>>() { });
    }

    @Override
    public ApplicationConfig get(final ApplicationRef ref) {
        return bridge.to(service.get(ref.realmId(), ref.name()).orElse(null), ApplicationConfig.class);
    }

    @Override
    public Boolean delete(final ApplicationRef ref) {
        return service.delete(ref.realmId(), ref.name());
    }
}
