package group.mfnr.authorization.amqp.resource.adapter;

import group.mfnr.authorization.amqp.resource.AllowedResourcesWrite;
import group.mfnr.authorization.amqp.resource.ResourceIndicatorPublisher;
import group.mfnr.authorization.service.resource.ResourceIndicatorService;
import group.mfnr.authorization.support.RealmScopedKey;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ResourceIndicatorPublisher}.
 */
@Component
public class ResourceIndicatorLocalAdapter implements ResourceIndicatorPublisher {

    private final ResourceIndicatorService service;

    public ResourceIndicatorLocalAdapter(final ResourceIndicatorService service) {
        this.service = service;
    }

    @Override
    public List<String> allowedResourcesForClient(final String clientId) {
        final String[] parts = RealmScopedKey.split(clientId);
        return service.resolveAllowedResourcesForClient(parts[0], parts[1]);
    }

    @Override
    public Boolean setAllowedResourcesForClient(final AllowedResourcesWrite write) {
        return service.updateAllowedResources(write.realmId(), write.clientId(), write.resources());
    }
}
