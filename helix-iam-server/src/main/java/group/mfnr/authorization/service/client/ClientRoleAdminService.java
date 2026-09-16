package group.mfnr.authorization.service.client;

import group.mfnr.authorization.domain.client.role.ClientRoleDto;
import group.mfnr.authorization.domain.client.role.ClientRoleEntity;
import group.mfnr.authorization.domain.client.role.ClientRoleWriteDto;
import group.mfnr.authorization.domain.client.role.ClientServiceAccountRoleEntity;
import group.mfnr.authorization.domain.client.role.ServiceAccountRoleDto;
import group.mfnr.authorization.repository.ClientRoleRepository;
import group.mfnr.authorization.repository.ClientServiceAccountRoleRepository;
import group.mfnr.authorization.repository.ServiceProviderRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Helix IAM (Wave 4): client-role administration + service-account role grants. Client roles are roles
 * scoped to a single client; a client's service account (its {@code client_credentials} identity) can be
 * granted realm roles and client roles, which {@link #serviceAccountRoleNamesForClient} surfaces into the
 * issued token's {@code roles} claim at issuance.
 */
@Service
public class ClientRoleAdminService {

    private static final Logger LOG = LogManager.getLogger(ClientRoleAdminService.class);

    private final ClientRoleRepository roles;
    private final ClientServiceAccountRoleRepository saRoles;
    private final ServiceProviderRepository clients;

    @Autowired
    public ClientRoleAdminService(final ClientRoleRepository roles,
                                  final ClientServiceAccountRoleRepository saRoles,
                                  final ServiceProviderRepository clients) {
        this.roles = roles;
        this.saRoles = saRoles;
        this.clients = clients;
    }

    /** The roles defined on a client. */
    @Transactional(readOnly = true)
    public List<ClientRoleDto> listClientRoles(final String realmId, final String clientId) {
        return roles.findAllByRealmIdAndClientIdOrderByName(realmId, clientId).stream().map(this::toDto).toList();
    }

    /** Defines a client role; idempotent on name within the client. */
    @Transactional
    public ClientRoleDto createClientRole(final ClientRoleWriteDto write) {
        // Invariant guard: a client role must have a name.
        if (write.name() == null || write.name().isBlank()) {
            throw new IllegalArgumentException("Role name is required.");
        }
        if (roles.existsByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())) {
            return roles.findByRealmIdAndClientIdAndName(write.realmId(), write.clientId(), write.name())
                    .map(this::toDto).orElse(null);
        }
        final ClientRoleEntity e = new ClientRoleEntity();
        e.setRealmId(write.realmId());
        e.setClientId(write.clientId());
        e.setName(write.name());
        e.setDescription(blankToNull(write.description()));
        LOG.debug("Created client role {} on {} in {}", write.name(), write.clientId(), write.realmId());
        return toDto(roles.save(e));
    }

    /** Removes a client role; {@code false} when absent. */
    @Transactional
    public boolean deleteClientRole(final String realmId, final String clientId, final String name) {
        return roles.findByRealmIdAndClientIdAndName(realmId, clientId, name).map(e -> {
            roles.delete(e);
            LOG.debug("Deleted client role {} from {} in {}", name, clientId, realmId);
            return true;
        }).orElse(false);
    }

    /** Roles granted to a client's service account. */
    @Transactional(readOnly = true)
    public List<ServiceAccountRoleDto> listServiceAccountRoles(final String realmId, final String clientId) {
        return saRoles.findAllByRealmIdAndClientIdOrderByRoleName(realmId, clientId).stream().map(this::toDto).toList();
    }

    /** Grants a role to a client's service account; idempotent on (role name, type). */
    @Transactional
    public ServiceAccountRoleDto assignServiceAccountRole(final ServiceAccountRoleDto write) {
        final String type = write.roleType() == null || write.roleType().isBlank() ? "REALM" : write.roleType();
        if (saRoles.findByRealmIdAndClientIdAndRoleNameAndRoleType(write.realmId(), write.clientId(), write.roleName(), type).isPresent()) {
            return write;
        }
        final ClientServiceAccountRoleEntity e = new ClientServiceAccountRoleEntity();
        e.setRealmId(write.realmId());
        e.setClientId(write.clientId());
        e.setRoleName(write.roleName());
        e.setRoleType(type);
        e.setRoleClientId(blankToNull(write.roleClientId()));
        LOG.debug("Granted {} role {} to service account of {} in {}", type, write.roleName(), write.clientId(), write.realmId());
        return toDto(saRoles.save(e));
    }

    /** Revokes a role from a client's service account; {@code false} when not granted. */
    @Transactional
    public boolean unassignServiceAccountRole(final String realmId, final String clientId, final String roleName, final String roleType) {
        final String type = roleType == null || roleType.isBlank() ? "REALM" : roleType;
        return saRoles.findByRealmIdAndClientIdAndRoleNameAndRoleType(realmId, clientId, roleName, type).map(e -> {
            saRoles.delete(e);
            LOG.debug("Revoked {} role {} from service account of {} in {}", type, roleName, clientId, realmId);
            return true;
        }).orElse(false);
    }

    /**
     * The role names granted to a client's service account ({@code client_id} <b>within {@code realmId}</b>).
     * Used by the token customizer for {@code client_credentials} tokens; empty when unknown. Realm-scoped
     * so a client id reused across realms resolves the right client.
     */
    @Transactional(readOnly = true)
    public List<String> serviceAccountRoleNamesForClient(final String realmId, final String clientId) {
        return clients.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false)
                .map(c -> saRoles.findAllByRealmIdAndClientIdOrderByRoleName(c.getTenantId(), clientId).stream()
                        .map(ClientServiceAccountRoleEntity::getRoleName).toList())
                .orElseGet(List::of);
    }

    /**
     * The typed (REALM/CLIENT) roles granted to a client's service account ({@code client_id} <b>within
     * {@code realmId}</b>). Used by the token customizer to namespace roles into {@code realm_access}/
     * {@code resource_access} for {@code client_credentials} tokens; empty when unknown. Realm-scoped so a
     * client id reused across realms resolves the right client.
     */
    @Transactional(readOnly = true)
    public List<ServiceAccountRoleDto> serviceAccountRolesForClient(final String realmId, final String clientId) {
        return clients.findByClientIdAndRealmIdAndDeleted(clientId, realmId, false)
                .map(c -> saRoles.findAllByRealmIdAndClientIdOrderByRoleName(c.getTenantId(), clientId).stream()
                        .map(this::toDto).toList())
                .orElseGet(List::of);
    }

    private ClientRoleDto toDto(final ClientRoleEntity e) {
        return new ClientRoleDto(e.getRoleId(), e.getRealmId(), e.getClientId(), e.getName(), e.getDescription());
    }

    private ServiceAccountRoleDto toDto(final ClientServiceAccountRoleEntity e) {
        return new ServiceAccountRoleDto(e.getId(), e.getRealmId(), e.getClientId(), e.getRoleName(), e.getRoleType(), e.getRoleClientId());
    }

    private static String blankToNull(final String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
