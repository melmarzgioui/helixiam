package io.helixiam.authorization.service.adminrbac;

import io.helixiam.authorization.domain.adminrbac.AdminPermission;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionEntity;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionRepository;
import io.helixiam.authorization.domain.adminrbac.admin.AdminEffectivePermissionsDto;
import io.helixiam.authorization.domain.adminrbac.admin.AdminRoleGrantWriteDto;
import io.helixiam.authorization.domain.adminrbac.admin.AdminRoleGrantsDto;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserRolesRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM: fine-grained admin RBAC — catalogue, role grants, default-safe effective-permission resolution. */
class AdminRbacServiceTest {

    private AdminRolePermissionRepository grants;
    private UserRolesRepository userRolesRepository;
    private AdminRbacService service;

    @BeforeEach
    void setUp() {
        grants = mock(AdminRolePermissionRepository.class);
        userRolesRepository = mock(UserRolesRepository.class);
        service = new AdminRbacService(grants, userRolesRepository);
    }

    @Test
    void catalog_coversEveryPermission() {
        assertEquals(AdminPermission.values().length, service.catalog().size());
        assertTrue(service.catalog().stream().anyMatch(p -> p.key().equals("manage-users")));
        assertTrue(service.catalog().stream().anyMatch(p -> p.key().equals("realm-admin")));
    }

    @Test
    void roles_joinsRealmRolesWithTheirGrants() {
        when(userRolesRepository.findAllByTenantId("gov")).thenReturn(List.of(role("r-1", "user-admin", "gov"),
                role("r-2", "auditor", "gov")));
        when(grants.findAllByRealmId("gov")).thenReturn(List.of(grant("gov", "r-1", AdminPermission.MANAGE_USERS),
                grant("gov", "r-1", AdminPermission.VIEW_USERS)));

        final List<AdminRoleGrantsDto> rows = service.roles("gov");

        final AdminRoleGrantsDto admin = rows.stream().filter(r -> r.roleId().equals("r-1")).findFirst().orElseThrow();
        assertEquals(List.of("view-users", "manage-users").size(), admin.permissions().size());
        assertTrue(admin.permissions().contains("manage-users"));
        final AdminRoleGrantsDto auditor = rows.stream().filter(r -> r.roleId().equals("r-2")).findFirst().orElseThrow();
        assertTrue(auditor.permissions().isEmpty());
    }

    @Test
    void setPermissions_replacesGrants_andRejectsUnknownKeys() {
        when(userRolesRepository.findById("r-1")).thenReturn(Optional.of(role("r-1", "user-admin", "gov")));
        when(grants.save(any(AdminRolePermissionEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        final AdminRoleGrantsDto out = service.setPermissions(
                new AdminRoleGrantWriteDto("gov", "r-1", List.of("manage-users", "view-users")));

        verify(grants).deleteByRealmIdAndRoleId("gov", "r-1");
        assertEquals(2, out.permissions().size());

        assertThrows(IllegalArgumentException.class, () ->
                service.setPermissions(new AdminRoleGrantWriteDto("gov", "r-1", List.of("not-a-real-permission"))));
    }

    @Test
    void setPermissions_rejectsCrossRealmRole() {
        when(userRolesRepository.findById("r-1")).thenReturn(Optional.of(role("r-1", "x", "other-realm")));
        assertThrows(IllegalArgumentException.class, () ->
                service.setPermissions(new AdminRoleGrantWriteDto("gov", "r-1", List.of("manage-users"))));
        verify(grants, never()).save(any());
    }

    @Test
    void effective_isUnconfigured_whenRealmHasNoGrants_default_safe_allow() {
        when(grants.countByRealmId("gov")).thenReturn(0L);
        final AdminEffectivePermissionsDto eff = service.effectivePermissions("gov", List.of("anything"));
        assertFalse(eff.modelConfigured());
        assertTrue(eff.permissions().isEmpty());
    }

    @Test
    void effective_resolvesRoleNamesToGrantedPermissions() {
        when(grants.countByRealmId("gov")).thenReturn(2L);
        when(userRolesRepository.findAllByTenantId("gov")).thenReturn(List.of(role("r-1", "user-admin", "gov")));
        when(grants.findAllByRealmIdAndRoleIdIn(eq("gov"), any())).thenReturn(
                List.of(grant("gov", "r-1", AdminPermission.MANAGE_USERS)));

        final AdminEffectivePermissionsDto eff = service.effectivePermissions("gov", List.of("user-admin"));

        assertTrue(eff.modelConfigured());
        assertEquals(List.of("manage-users"), eff.permissions());
    }

    @Test
    void effective_matchesTenantQualifiedRoleName_asCarriedBySessionAuthorities() {
        // A logged-in principal's authorities are the tenant-qualified role names (name + "_" + realmId).
        when(grants.countByRealmId("gov")).thenReturn(2L);
        when(userRolesRepository.findAllByTenantId("gov")).thenReturn(List.of(role("r-1", "user-admin", "gov")));
        when(grants.findAllByRealmIdAndRoleIdIn(eq("gov"), any())).thenReturn(
                List.of(grant("gov", "r-1", AdminPermission.MANAGE_USERS)));

        final AdminEffectivePermissionsDto eff = service.effectivePermissions("gov", List.of("user-admin_gov"));

        assertTrue(eff.modelConfigured());
        assertEquals(List.of("manage-users"), eff.permissions());
    }

    @Test
    void effective_realmAdminExpandsToEveryPermission() {
        when(grants.countByRealmId("gov")).thenReturn(1L);
        when(userRolesRepository.findAllByTenantId("gov")).thenReturn(List.of(role("r-1", "superadmin", "gov")));
        when(grants.findAllByRealmIdAndRoleIdIn(eq("gov"), any())).thenReturn(
                List.of(grant("gov", "r-1", AdminPermission.REALM_ADMIN)));

        final AdminEffectivePermissionsDto eff = service.effectivePermissions("gov", List.of("superadmin"));

        assertEquals(AdminPermission.values().length, eff.permissions().size());
        assertTrue(eff.permissions().contains("manage-clients"));
    }

    @Test
    void effective_configuredRealm_principalWithNoMatchingRole_getsNothing() {
        when(grants.countByRealmId("gov")).thenReturn(3L);
        when(userRolesRepository.findAllByTenantId("gov")).thenReturn(List.of(role("r-1", "user-admin", "gov")));
        final AdminEffectivePermissionsDto eff = service.effectivePermissions("gov", List.of("unrelated-role"));
        assertTrue(eff.modelConfigured());
        assertTrue(eff.permissions().isEmpty());
    }

    private static UserRoles role(final String roleId, final String name, final String tenantId) {
        // Real object (not a mock): mocking here was called inside an outer when(...).thenReturn(List.of(role(...)))
        // which nests stubbing and trips Mockito's UnfinishedStubbing. roleId is generated (no setter) so set it
        // via reflection.
        final UserRoles r = new UserRoles(name, tenantId);
        try {
            final java.lang.reflect.Field f = UserRoles.class.getDeclaredField("roleId");
            f.setAccessible(true);
            f.set(r, roleId);
        } catch (final ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
        return r;
    }

    private static AdminRolePermissionEntity grant(final String realmId, final String roleId, final AdminPermission p) {
        final AdminRolePermissionEntity e = new AdminRolePermissionEntity();
        e.setRealmId(realmId);
        e.setRoleId(roleId);
        e.setPermission(p.name());
        return e;
    }
}
