/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.role;

import io.helixiam.authorization.domain.adminrbac.AdminPermission;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionEntity;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionRepository;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserRolesRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Helix IAM: curated default-role seeding — admin/user/auditor per realm, idempotent, with admin-permission grants. */
class DefaultRolesBootstrapServiceTest {

    private UserRolesRepository roles;
    private AdminRolePermissionRepository grants;
    private DefaultRolesBootstrapService service;

    @BeforeEach
    void setUp() {
        roles = mock(UserRolesRepository.class);
        grants = mock(AdminRolePermissionRepository.class);
        service = new DefaultRolesBootstrapService(roles, grants);
    }

    @Test
    void seedsAdminUserAuditorWithFlagsAndGrantsOnFreshRealm() {
        // fresh realm: nothing exists, no grants
        when(roles.findByTenantIdAndName(anyString(), anyString())).thenReturn(Optional.empty());
        when(grants.findAllByRealmIdAndRoleId(anyString(), anyString())).thenReturn(List.of());
        // save returns the entity with a synthetic id so grants can reference it
        final AtomicInteger seq = new AtomicInteger();
        when(roles.save(any(UserRoles.class))).thenAnswer(inv -> {
            final UserRoles in = inv.getArgument(0);
            return new UserRoles("role-" + seq.incrementAndGet(), in.getName(), in.getTenantId(),
                    in.isSystemRole(), in.isDefaultRole());
        });

        service.ensureDefaultRoles("acme");

        final ArgumentCaptor<UserRoles> savedRoles = ArgumentCaptor.forClass(UserRoles.class);
        verify(roles, org.mockito.Mockito.times(3)).save(savedRoles.capture());
        final List<UserRoles> created = savedRoles.getAllValues();
        assertEquals(List.of("admin", "user", "auditor"), created.stream().map(UserRoles::getName).toList());
        // all curated roles are system-protected
        assertTrue(created.stream().allMatch(UserRoles::isSystemRole), "curated roles must be system");
        // exactly 'user' is the default role
        assertEquals(List.of("user"),
                created.stream().filter(UserRoles::isDefaultRole).map(UserRoles::getName).toList());

        // grants: admin→REALM_ADMIN (1) + auditor→view-users/view-clients/view-events (3) = 4
        final ArgumentCaptor<AdminRolePermissionEntity> savedGrants = ArgumentCaptor.forClass(AdminRolePermissionEntity.class);
        verify(grants, org.mockito.Mockito.times(4)).save(savedGrants.capture());
        final List<String> perms = new ArrayList<>(savedGrants.getAllValues().stream()
                .map(AdminRolePermissionEntity::getPermission).toList());
        assertTrue(perms.contains(AdminPermission.REALM_ADMIN.name()));
        assertTrue(perms.contains(AdminPermission.VIEW_USERS.name()));
        assertTrue(perms.contains(AdminPermission.VIEW_CLIENTS.name()));
        assertTrue(perms.contains(AdminPermission.VIEW_EVENTS.name()));
    }

    @Test
    void isIdempotent_whenAllRolesExistWithFlagsAndGrants_writesNothing() {
        final UserRoles admin = new UserRoles("r-admin", "admin", "acme", true, false);
        final UserRoles user = new UserRoles("r-user", "user", "acme", true, true);
        final UserRoles auditor = new UserRoles("r-aud", "auditor", "acme", true, false);
        when(roles.findByTenantIdAndName("acme", "admin")).thenReturn(Optional.of(admin));
        when(roles.findByTenantIdAndName("acme", "user")).thenReturn(Optional.of(user));
        when(roles.findByTenantIdAndName("acme", "auditor")).thenReturn(Optional.of(auditor));
        when(grants.findAllByRealmIdAndRoleId("acme", "r-admin"))
                .thenReturn(List.of(grant("acme", "r-admin", AdminPermission.REALM_ADMIN)));
        when(grants.findAllByRealmIdAndRoleId("acme", "r-aud")).thenReturn(List.of(
                grant("acme", "r-aud", AdminPermission.VIEW_USERS),
                grant("acme", "r-aud", AdminPermission.VIEW_CLIENTS),
                grant("acme", "r-aud", AdminPermission.VIEW_EVENTS)));
        when(grants.findAllByRealmIdAndRoleId("acme", "r-user")).thenReturn(List.of());

        service.ensureDefaultRoles("acme");

        verify(roles, never()).save(any());
        verify(grants, never()).save(any());
    }

    @Test
    void upgradesExistingAdmin_setsSystemFlagAndEnsuresGrant() {
        // existing realm where 'admin' was seeded by the old bootstrap: no flags, no grant
        final UserRoles legacyAdmin = new UserRoles("r-admin", "admin", "acme", false, false);
        when(roles.findByTenantIdAndName("acme", "admin")).thenReturn(Optional.of(legacyAdmin));
        when(roles.findByTenantIdAndName(eq("acme"), eq("user"))).thenReturn(Optional.empty());
        when(roles.findByTenantIdAndName(eq("acme"), eq("auditor"))).thenReturn(Optional.empty());
        when(grants.findAllByRealmIdAndRoleId("acme", "r-admin")).thenReturn(List.of());
        when(roles.save(any(UserRoles.class))).thenAnswer(inv -> inv.getArgument(0));

        service.ensureDefaultRoles("acme");

        // admin got its system flag set (idempotent upgrade)
        assertTrue(legacyAdmin.isSystemRole());
        // and the realm-admin grant was ensured
        final ArgumentCaptor<AdminRolePermissionEntity> g = ArgumentCaptor.forClass(AdminRolePermissionEntity.class);
        verify(grants, org.mockito.Mockito.atLeastOnce()).save(g.capture());
        assertTrue(g.getAllValues().stream().anyMatch(x ->
                "r-admin".equals(x.getRoleId()) && AdminPermission.REALM_ADMIN.name().equals(x.getPermission())));
    }

    private static AdminRolePermissionEntity grant(final String realm, final String roleId, final AdminPermission p) {
        final AdminRolePermissionEntity e = new AdminRolePermissionEntity();
        e.setRealmId(realm);
        e.setRoleId(roleId);
        e.setPermission(p.name());
        return e;
    }
}
