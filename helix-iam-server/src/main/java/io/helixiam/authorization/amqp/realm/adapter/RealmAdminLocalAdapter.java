package io.helixiam.authorization.amqp.realm.adapter;

import io.helixiam.authorization.amqp.realm.RealmAdminPublisher;
import io.helixiam.authorization.amqp.realm.RealmSettingsDto;
import io.helixiam.authorization.amqp.support.DtoBridge;
import io.helixiam.authorization.service.realm.RealmAdminService;
import org.springframework.stereotype.Component;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link RealmAdminPublisher}.
 */
@Component
public class RealmAdminLocalAdapter implements RealmAdminPublisher {

    private final RealmAdminService service;
    private final DtoBridge bridge;

    public RealmAdminLocalAdapter(final RealmAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public RealmSettingsDto get(final String realmId) {
        return bridge.to(service.get(realmId), RealmSettingsDto.class);
    }

    @Override
    public RealmSettingsDto save(final RealmSettingsDto dto) {
        return bridge.to(service.save(
                bridge.to(dto, io.helixiam.authorization.domain.realm.admin.RealmSettingsDto.class)),
                RealmSettingsDto.class);
    }

    @Override
    public Boolean exists(final String realmId) {
        return service.exists(realmId);
    }
}
