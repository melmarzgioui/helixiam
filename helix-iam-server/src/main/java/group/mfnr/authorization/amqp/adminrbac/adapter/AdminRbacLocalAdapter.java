package group.mfnr.authorization.amqp.adminrbac.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.adminrbac.AdminEffectivePermissionsDto;
import group.mfnr.authorization.amqp.adminrbac.AdminEffectivePermissionsRef;
import group.mfnr.authorization.amqp.adminrbac.AdminPermissionDto;
import group.mfnr.authorization.amqp.adminrbac.AdminRbacPublisher;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantWriteDto;
import group.mfnr.authorization.amqp.adminrbac.AdminRoleGrantsDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.adminrbac.AdminRbacService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link AdminRbacPublisher}.
 */
@Component
public class AdminRbacLocalAdapter implements AdminRbacPublisher {

    private final AdminRbacService service;
    private final DtoBridge bridge;

    public AdminRbacLocalAdapter(final AdminRbacService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<AdminPermissionDto> catalog(final String arg) {
        return bridge.to(service.catalog(), new TypeReference<List<AdminPermissionDto>>() { });
    }

    @Override
    public List<AdminRoleGrantsDto> roles(final String realmId) {
        return bridge.to(service.roles(realmId), new TypeReference<List<AdminRoleGrantsDto>>() { });
    }

    @Override
    public AdminRoleGrantsDto set(final AdminRoleGrantWriteDto write) {
        return bridge.to(service.setPermissions(
                bridge.to(write, group.mfnr.authorization.domain.adminrbac.admin.AdminRoleGrantWriteDto.class)),
                AdminRoleGrantsDto.class);
    }

    @Override
    public AdminEffectivePermissionsDto effective(final AdminEffectivePermissionsRef ref) {
        return bridge.to(service.effectivePermissions(ref.realmId(), ref.roleNames()),
                AdminEffectivePermissionsDto.class);
    }
}
