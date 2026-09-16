package group.mfnr.authorization.amqp.role.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.role.RoleAdminPublisher;
import group.mfnr.authorization.amqp.role.RoleAssignment;
import group.mfnr.authorization.amqp.role.RoleDto;
import group.mfnr.authorization.amqp.role.RoleRef;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.role.RoleAdminService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link RoleAdminPublisher}.
 */
@Component
public class RoleAdminLocalAdapter implements RoleAdminPublisher {

    private final RoleAdminService service;
    private final DtoBridge bridge;

    public RoleAdminLocalAdapter(final RoleAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<RoleDto> list(final String realmId) {
        return bridge.to(service.list(realmId), new TypeReference<List<RoleDto>>() { });
    }

    @Override
    public RoleDto create(final RoleRef ref) {
        return bridge.to(service.create(ref.realmId(), ref.name()), RoleDto.class);
    }

    @Override
    public Boolean delete(final RoleRef ref) {
        return service.delete(ref.realmId(), ref.roleId());
    }

    @Override
    public List<RoleDto> userRoles(final RoleAssignment ref) {
        return bridge.to(service.userRoles(ref.realmId(), ref.userId()), new TypeReference<List<RoleDto>>() { });
    }

    @Override
    public Boolean assign(final RoleAssignment ref) {
        return service.assign(ref.realmId(), ref.userId(), ref.roleId());
    }

    @Override
    public Boolean unassign(final RoleAssignment ref) {
        return service.unassign(ref.realmId(), ref.userId(), ref.roleId());
    }

    @Override
    public RoleDto setDefault(final RoleRef ref) {
        return bridge.to(service.setDefault(ref.realmId(), ref.roleId()), RoleDto.class);
    }
}
