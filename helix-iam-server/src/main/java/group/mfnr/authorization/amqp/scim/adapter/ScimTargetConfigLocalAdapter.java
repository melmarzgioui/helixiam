package group.mfnr.authorization.amqp.scim.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.scim.ScimTargetConfigPublisher;
import group.mfnr.authorization.amqp.scim.ScimTargetDto;
import group.mfnr.authorization.amqp.scim.ScimTargetRef;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.scim.ScimTargetAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ScimTargetConfigPublisher}.
 */
@Component
public class ScimTargetConfigLocalAdapter implements ScimTargetConfigPublisher {

    private final ScimTargetAdminService service;
    private final DtoBridge bridge;

    public ScimTargetConfigLocalAdapter(final ScimTargetAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<ScimTargetDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<ScimTargetDto>>() { });
    }

    @Override
    public List<ScimTargetDto> active(final String realmId) {
        return bridge.to(service.active(realmId), new TypeReference<List<ScimTargetDto>>() { });
    }

    @Override
    public ScimTargetDto save(final ScimTargetDto target) {
        return bridge.to(service.save(
                bridge.to(target, group.mfnr.authorization.domain.scim.ScimTargetDto.class)),
                ScimTargetDto.class);
    }

    @Override
    public Boolean delete(final ScimTargetRef ref) {
        return service.delete(ref.realmId(), ref.id());
    }
}
