package group.mfnr.authorization.amqp.webhook.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.amqp.webhook.WebhookConfigPublisher;
import group.mfnr.authorization.amqp.webhook.WebhookRef;
import group.mfnr.authorization.amqp.webhook.WebhookSubscriptionDto;
import group.mfnr.authorization.service.webhook.WebhookAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link WebhookConfigPublisher}.
 */
@Component
public class WebhookConfigLocalAdapter implements WebhookConfigPublisher {

    private final WebhookAdminService service;
    private final DtoBridge bridge;

    public WebhookConfigLocalAdapter(final WebhookAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<WebhookSubscriptionDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<WebhookSubscriptionDto>>() { });
    }

    @Override
    public List<WebhookSubscriptionDto> active(final String realmId) {
        return bridge.to(service.active(realmId), new TypeReference<List<WebhookSubscriptionDto>>() { });
    }

    @Override
    public WebhookSubscriptionDto save(final WebhookSubscriptionDto dto) {
        return bridge.to(service.save(
                bridge.to(dto, group.mfnr.authorization.domain.webhook.WebhookSubscriptionDto.class)),
                WebhookSubscriptionDto.class);
    }

    @Override
    public Boolean delete(final WebhookRef ref) {
        return service.delete(ref.realmId(), ref.id());
    }
}
