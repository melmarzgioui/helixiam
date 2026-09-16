package group.mfnr.authorization.amqp.realm.adapter;

import group.mfnr.authorization.amqp.realm.RealmAdminPublisher;
import group.mfnr.authorization.amqp.realm.RealmSettingsDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.realm.RealmAdminService;
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
                bridge.to(dto, group.mfnr.authorization.domain.realm.admin.RealmSettingsDto.class)),
                RealmSettingsDto.class);
    }

    @Override
    public Boolean exists(final String realmId) {
        return service.exists(realmId);
    }
}
