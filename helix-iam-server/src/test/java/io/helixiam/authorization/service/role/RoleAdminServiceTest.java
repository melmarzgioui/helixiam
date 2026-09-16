package io.helixiam.authorization.service.role;

import io.helixiam.authorization.domain.role.admin.RoleDto;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserInRole;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.5-S2: realm role administration + assignment.
 */
class RoleAdminServiceTest {

    private UserRolesRepository userRolesRepository;
    private UserInRoleRepository userInRoleRepository;
    private TenantUserRepository tenantUserRepository;
    private RoleAdminService service;

    @BeforeEach
    void setUp() {
        userRolesRepository = mock(UserRolesRepository.class);
        userInRoleRepository = mock(UserInRoleRepository.class);
        tenantUserRepository = mock(TenantUserRepository.class);
        service = new RoleAdminService(userRolesRepository, userInRoleRepository, tenantUserRepository);
    }

    @Test
    void list_returnsRealmRoles() {
        when(userRolesRepository.findAllByTenantId("gov")).thenReturn(List.of(role("auditor", "gov"), role("approver", "gov")));
        final List<RoleDto> roles = service.list("gov");
        assertEquals(List.of("approver", "auditor"), roles.stream().map(RoleDto::name).sorted().toList());
    }

    @Test
    void create_persistsNewRole_andIsIdempotentOnDuplicate() {
        when(userRolesRepository.existsByTenantIdAndName("gov", "auditor")).thenReturn(false);
        when(userRolesRepository.save(any(UserRoles.class))).thenAnswer(inv -> inv.getArgument(0));

        service.create("gov", "auditor");

        final ArgumentCaptor<UserRoles> captor = ArgumentCaptor.forClass(UserRoles.class);
        verify(userRolesRepository).save(captor.capture());
        assertEquals("auditor", captor.getValue().getName());
        assertEquals("gov", captor.getValue().getTenantId());

        // duplicate: do not create a second row
        when(userRolesRepository.existsByTenantIdAndName("gov", "auditor")).thenReturn(true);
        when(userRolesRepository.findByTenantIdAndName("gov", "auditor")).thenReturn(Optional.of(role("auditor", "gov")));
        service.create("gov", "auditor");
        verify(userRolesRepository, never()).save(role("auditor", "gov")); // (new instance) — still only the first save
    }

    @Test
    void create_rejectsBlankName() {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.create("gov", "  "));
        assertEquals("Role name is required.", ex.getMessage());
        verify(userRolesRepository, never()).save(any());
    }

    @Test
    void delete_removesAssignmentsThenRole_whenRoleBelongsToRealm() {
        final UserRoles role = role("auditor", "gov");
        when(userRolesRepository.findById("r-1")).thenReturn(Optional.of(role));
        when(userInRoleRepository.findAllByRoleId("r-1")).thenReturn(List.of(new UserInRole("r-1", "u-1", "tu-1")));

        assertTrue(service.delete("gov", "r-1"));

        verify(userInRoleRepository).deleteAll(any());
        verify(userRolesRepository).delete(role);
    }

    @Test
    void delete_refuses_whenRoleBelongsToAnotherRealm() {
        when(userRolesRepository.findById("r-1")).thenReturn(Optional.of(role("auditor", "internal")));
        assertFalse(service.delete("gov", "r-1"));
        verify(userRolesRepository, never()).delete(any());
    }

    @Test
    void delete_refuses_whenRoleIsProtectedSystemRole() {
        final UserRoles system = new UserRoles("admin", "gov", true, false);
        when(userRolesRepository.findById("r-1")).thenReturn(Optional.of(system));
        assertFalse(service.delete("gov", "r-1"));
        verify(userRolesRepository, never()).delete(any());
        verify(userInRoleRepository, never()).deleteAll(any());
    }

    @Test
    void list_carriesSystemAndDefaultFlags() {
        when(userRolesRepository.findAllByTenantId("gov"))
                .thenReturn(List.of(new UserRoles("user", "gov", true, true)));
        final RoleDto dto = service.list("gov").get(0);
        assertTrue(dto.system());
        assertTrue(dto.defaultRole());
    }

    @Test
    void setDefault_setsTarget_andClearsPreviousDefault() {
        final UserRoles target = new UserRoles("auditor", "auditor", "gov", false, false);
        final UserRoles previous = new UserRoles("user", "user", "gov", true, true);
        when(userRolesRepository.findById("auditor")).thenReturn(Optional.of(target));
        when(userRolesRepository.findAllByTenantIdAndDefaultRoleTrue("gov")).thenReturn(List.of(previous));
        when(userRolesRepository.save(any(UserRoles.class))).thenAnswer(inv -> inv.getArgument(0));

        final RoleDto dto = service.setDefault("gov", "auditor");

        assertTrue(dto.defaultRole());
        assertFalse(previous.isDefaultRole()); // prior default cleared
        assertTrue(target.isDefaultRole());    // target promoted
        verify(userRolesRepository).save(previous);
        verify(userRolesRepository).save(target);
    }

    @Test
    void setDefault_returnsNull_whenRoleNotInRealm() {
        when(userRolesRepository.findById("r-9")).thenReturn(Optional.of(role("auditor", "other")));
        assertNull(service.setDefault("gov", "r-9"));
        verify(userRolesRepository, never()).save(any());
    }

    @Test
    void assign_createsUserInRole_whenNotAlreadyAssigned() {
        final TenantUser link = new TenantUser();
        link.setTenantId("gov");
        link.setUserId("u-1");
        when(tenantUserRepository.findByTenantIdAndUserId("gov", "u-1")).thenReturn(Optional.of(link));
        when(userInRoleRepository.findByRoleIdAndUserId("r-1", "u-1")).thenReturn(Optional.empty());

        assertTrue(service.assign("gov", "u-1", "r-1"));
        verify(userInRoleRepository).save(any(UserInRole.class));
    }

    @Test
    void unassign_deletesUserInRole_whenPresent() {
        final UserInRole uir = new UserInRole("r-1", "u-1", "tu-1");
        when(userInRoleRepository.findByRoleIdAndUserId("r-1", "u-1")).thenReturn(Optional.of(uir));
        assertTrue(service.unassign("gov", "u-1", "r-1"));
        verify(userInRoleRepository).delete(uir);
    }

    private static UserRoles role(final String name, final String tenantId) {
        return new UserRoles(name, tenantId);
    }
}
