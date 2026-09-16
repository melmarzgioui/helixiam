package group.mfnr.authorization.service.client;

import group.mfnr.authorization.domain.ServiceProviderOAuthClient;
import group.mfnr.authorization.domain.client.role.ClientRoleDto;
import group.mfnr.authorization.domain.client.role.ClientRoleWriteDto;
import group.mfnr.authorization.domain.client.role.ClientServiceAccountRoleEntity;
import group.mfnr.authorization.domain.client.role.ClientRoleEntity;
import group.mfnr.authorization.domain.client.role.ServiceAccountRoleDto;
import group.mfnr.authorization.repository.ClientRoleRepository;
import group.mfnr.authorization.repository.ClientServiceAccountRoleRepository;
import group.mfnr.authorization.repository.ServiceProviderRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM (Wave 4): client roles + service-account role grants. */
class ClientRoleAdminServiceTest {

    private ClientRoleRepository roles;
    private ClientServiceAccountRoleRepository saRoles;
    private ServiceProviderRepository clients;
    private ClientRoleAdminService service;

    @BeforeEach
    void setUp() {
        roles = mock(ClientRoleRepository.class);
        saRoles = mock(ClientServiceAccountRoleRepository.class);
        clients = mock(ServiceProviderRepository.class);
        service = new ClientRoleAdminService(roles, saRoles, clients);
    }

    @Test
    void createClientRole_persists_andIsIdempotentOnName() {
        when(roles.existsByRealmIdAndClientIdAndName("gov", "portal", "viewer")).thenReturn(false);
        when(roles.save(any(ClientRoleEntity.class))).thenAnswer(i -> i.getArgument(0));
        final ClientRoleDto dto = service.createClientRole(new ClientRoleWriteDto("gov", "portal", "viewer", "Read only"));
        assertEquals("viewer", dto.name());
        assertEquals("Read only", dto.description());

        // second create with the same name returns the existing one (no duplicate save)
        final ClientRoleEntity existing = new ClientRoleEntity();
        existing.setRealmId("gov"); existing.setClientId("portal"); existing.setName("viewer");
        when(roles.existsByRealmIdAndClientIdAndName("gov", "portal", "viewer")).thenReturn(true);
        when(roles.findByRealmIdAndClientIdAndName("gov", "portal", "viewer")).thenReturn(Optional.of(existing));
        final ClientRoleDto again = service.createClientRole(new ClientRoleWriteDto("gov", "portal", "viewer", "x"));
        assertEquals("viewer", again.name());
    }

    @Test
    void createClientRole_rejectsBlankName() {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.createClientRole(new ClientRoleWriteDto("gov", "portal", "  ", "x")));
        assertEquals("Role name is required.", ex.getMessage());
        verify(roles, never()).save(any(ClientRoleEntity.class));
    }

    @Test
    void deleteClientRole_returnsFalse_whenAbsent() {
        when(roles.findByRealmIdAndClientIdAndName("gov", "portal", "nope")).thenReturn(Optional.empty());
        assertFalse(service.deleteClientRole("gov", "portal", "nope"));
    }

    @Test
    void assignServiceAccountRole_isIdempotent() {
        when(saRoles.findByRealmIdAndClientIdAndRoleNameAndRoleType("gov", "portal", "admin", "REALM"))
                .thenReturn(Optional.empty());
        when(saRoles.save(any(ClientServiceAccountRoleEntity.class))).thenAnswer(i -> i.getArgument(0));
        final ServiceAccountRoleDto dto = service.assignServiceAccountRole(
                new ServiceAccountRoleDto(null, "gov", "portal", "admin", "REALM", null));
        assertEquals("admin", dto.roleName());
        verify(saRoles).save(any(ClientServiceAccountRoleEntity.class));

        // already-assigned → no second save
        final ClientServiceAccountRoleEntity e = new ClientServiceAccountRoleEntity();
        e.setRealmId("gov"); e.setClientId("portal"); e.setRoleName("admin"); e.setRoleType("REALM");
        when(saRoles.findByRealmIdAndClientIdAndRoleNameAndRoleType("gov", "portal", "admin", "REALM"))
                .thenReturn(Optional.of(e));
        service.assignServiceAccountRole(new ServiceAccountRoleDto(null, "gov", "portal", "admin", "REALM", null));
        verify(saRoles, never()).delete(any());
    }

    @Test
    void serviceAccountRoleNamesForClient_resolvesRealm_thenReturnsNames() {
        final ServiceProviderOAuthClient c = new ServiceProviderOAuthClient();
        c.setClientId("portal"); c.setTenantId("gov");
        when(clients.findByClientIdAndRealmIdAndDeleted("portal", "gov", false)).thenReturn(Optional.of(c));
        final ClientServiceAccountRoleEntity a = new ClientServiceAccountRoleEntity();
        a.setRoleName("admin"); a.setRoleType("REALM");
        final ClientServiceAccountRoleEntity b = new ClientServiceAccountRoleEntity();
        b.setRoleName("viewer"); b.setRoleType("CLIENT");
        when(saRoles.findAllByRealmIdAndClientIdOrderByRoleName("gov", "portal")).thenReturn(List.of(a, b));

        final List<String> names = service.serviceAccountRoleNamesForClient("gov", "portal");
        assertTrue(names.contains("admin"));
        assertTrue(names.contains("viewer"));
    }

    @Test
    void serviceAccountRoleNamesForClient_emptyWhenClientUnknown() {
        when(clients.findByClientIdAndRealmIdAndDeleted("ghost", "gov", false)).thenReturn(Optional.empty());
        assertTrue(service.serviceAccountRoleNamesForClient("gov", "ghost").isEmpty());
    }
}
