package io.helixiam.authorization.amqp.key.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import io.helixiam.authorization.amqp.key.RealmKeyConfigPublisher;
import io.helixiam.authorization.amqp.key.RealmKeyView;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.key.RealmKeyService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link RealmKeyConfigPublisher}. Only public key material crosses to the pub-side view (as before).
 */
@Component
public class RealmKeyConfigLocalAdapter implements RealmKeyConfigPublisher {

    private final RealmKeyService service;
    private final DtoBridge bridge;

    public RealmKeyConfigLocalAdapter(final RealmKeyService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<RealmKeyView> list(final String realmId) {
        return bridge.to(service.listViews(realmId), new TypeReference<List<RealmKeyView>>() { });
    }

    @Override
    public RealmKeyView rotate(final String realmId) {
        return bridge.to(
                io.helixiam.authorization.domain.realm.RealmKeyView.from(service.rotate(realmId)),
                RealmKeyView.class);
    }

    @Override
    public Boolean retire(final String keyId) {
        return service.retire(keyId);
    }
}
