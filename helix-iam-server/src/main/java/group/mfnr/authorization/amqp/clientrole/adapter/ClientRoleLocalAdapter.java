package group.mfnr.authorization.amqp.clientrole.adapter;

import com.fasterxml.jackson.core.type.TypeReference;
import group.mfnr.authorization.amqp.clientrole.ClientRoleDto;
import group.mfnr.authorization.amqp.clientrole.ClientRolePublisher;
import group.mfnr.authorization.amqp.clientrole.ClientRoleRef;
import group.mfnr.authorization.amqp.clientrole.ClientRoleWriteDto;
import group.mfnr.authorization.amqp.clientrole.ServiceAccountRoleDto;
import group.mfnr.authorization.amqp.support.DtoBridge;
import group.mfnr.authorization.service.client.ClientRoleAdminService;
import group.mfnr.authorization.support.RealmScopedKey;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Strip-RabbitMQ (Task 3): in-process adapter replacing the former AMQP transport of
 * {@link ClientRolePublisher}.
 */
@Component
public class ClientRoleLocalAdapter implements ClientRolePublisher {

    private final ClientRoleAdminService service;
    private final DtoBridge bridge;

    public ClientRoleLocalAdapter(final ClientRoleAdminService service, final DtoBridge bridge) {
        this.service = service;
        this.bridge = bridge;
    }

    @Override
    public List<ClientRoleDto> listRoles(final ClientRoleRef ref) {
        return bridge.to(service.listClientRoles(ref.realmId(), ref.clientId()),
                new TypeReference<List<ClientRoleDto>>() { });
    }

    @Override
    public ClientRoleDto createRole(final ClientRoleWriteDto write) {
        return bridge.to(service.createClientRole(
                bridge.to(write, group.mfnr.authorization.domain.client.role.ClientRoleWriteDto.class)),
                ClientRoleDto.class);
    }

    @Override
    public Boolean deleteRole(final ClientRoleRef ref) {
        return service.deleteClientRole(ref.realmId(), ref.clientId(), ref.name());
    }

    @Override
    public List<ServiceAccountRoleDto> listServiceAccountRoles(final ClientRoleRef ref) {
        return bridge.to(service.listServiceAccountRoles(ref.realmId(), ref.clientId()),
                new TypeReference<List<ServiceAccountRoleDto>>() { });
    }

    @Override
    public ServiceAccountRoleDto assignServiceAccountRole(final ServiceAccountRoleDto write) {
        return bridge.to(service.assignServiceAccountRole(
                bridge.to(write, group.mfnr.authorization.domain.client.role.ServiceAccountRoleDto.class)),
                ServiceAccountRoleDto.class);
    }

    @Override
    public Boolean unassignServiceAccountRole(final ServiceAccountRoleDto ref) {
        return service.unassignServiceAccountRole(ref.realmId(), ref.clientId(), ref.roleName(), ref.roleType());
    }

    @Override
    public List<String> serviceAccountRoleNames(final String clientId) {
        final String[] parts = RealmScopedKey.split(clientId);
        return new ArrayList<>(service.serviceAccountRoleNamesForClient(parts[0], parts[1]));
    }

    @Override
    public List<ServiceAccountRoleDto> serviceAccountRoles(final String clientId) {
        final String[] parts = RealmScopedKey.split(clientId);
        return bridge.to(service.serviceAccountRolesForClient(parts[0], parts[1]),
                new TypeReference<List<ServiceAccountRoleDto>>() { });
    }
}
