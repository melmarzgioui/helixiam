/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.adminrbac;

import io.helixiam.authorization.domain.adminrbac.AdminPermission;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionEntity;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionRepository;
import io.helixiam.authorization.domain.adminrbac.admin.AdminEffectivePermissionsDto;
import io.helixiam.authorization.domain.adminrbac.admin.AdminPermissionDto;
import io.helixiam.authorization.domain.adminrbac.admin.AdminRoleGrantWriteDto;
import io.helixiam.authorization.domain.adminrbac.admin.AdminRoleGrantsDto;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserRolesRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Helix IAM: fine-grained admin RBAC — maps realm (admin) roles to a composable set of {@link AdminPermission}s
 * (the Keycloak {@code realm-management} / WorkOS-class scoped-admin model). Persistence side of the console's
 * "Admin roles" matrix and of the publisher's {@code AdminAuthorizationManager} enforcement check.
 * <p>
 * Default-safe: when a realm has NO grants at all the model is "unconfigured" and any authenticated admin is
 * allowed (behaves exactly as today). {@link AdminPermission#REALM_ADMIN} implies every permission.
 */
@Service
public class AdminRbacService {

    private static final Logger LOG = LogManager.getLogger(AdminRbacService.class);

    private final AdminRolePermissionRepository grants;
    private final UserRolesRepository userRolesRepository;

    @Autowired
    public AdminRbacService(final AdminRolePermissionRepository grants,
                            final UserRolesRepository userRolesRepository) {
        this.grants = grants;
        this.userRolesRepository = userRolesRepository;
    }

    /** The full catalogue of admin permissions (the matrix columns). Independent of realm. */
    public List<AdminPermissionDto> catalog() {
        return Arrays.stream(AdminPermission.values())
                .map(p -> new AdminPermissionDto(p.key(), p.label()))
                .toList();
    }

    /** Every realm role with the admin-permission keys it currently grants (matrix rows). */
    public List<AdminRoleGrantsDto> roles(final String realmId) {
        final List<AdminRolePermissionEntity> all = grants.findAllByRealmId(realmId);
        return userRolesRepository.findAllByTenantId(realmId).stream()
                .map(role -> new AdminRoleGrantsDto(realmId, role.getRoleId(), role.getName(),
                        all.stream()
                                .filter(g -> role.getRoleId().equals(g.getRoleId()))
                                .map(g -> AdminPermission.from(g.getPermission()))
                                .filter(Optional::isPresent).map(Optional::get)
                                .map(AdminPermission::key)
                                .distinct().toList()))
                .toList();
    }

    /**
     * Replaces the complete set of admin permissions granted to one realm role. Unknown permission keys are
     * rejected; the role must belong to the realm. Idempotent (delete-then-insert the target set).
     */
    @Transactional
    public AdminRoleGrantsDto setPermissions(final AdminRoleGrantWriteDto write) {
        if (write == null || write.realmId() == null || write.realmId().isBlank()) {
            throw new IllegalArgumentException("Realm is required.");
        }
        if (write.roleId() == null || write.roleId().isBlank()) {
            throw new IllegalArgumentException("Role is required.");
        }
        final Optional<UserRoles> role = userRolesRepository.findById(write.roleId());
        if (role.isEmpty() || !write.realmId().equals(role.get().getTenantId())) {
            throw new IllegalArgumentException("Role does not belong to this realm.");
        }
        // Validate + normalise every requested permission to its enum (rejects typos up front).
        final Set<AdminPermission> requested = new LinkedHashSet<>();
        for (final String key : write.permissions() == null ? List.<String>of() : write.permissions()) {
            requested.add(AdminPermission.from(key)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown admin permission: " + key)));
        }
        grants.deleteByRealmIdAndRoleId(write.realmId(), write.roleId());
        for (final AdminPermission p : requested) {
            final AdminRolePermissionEntity row = new AdminRolePermissionEntity();
            row.setRealmId(write.realmId());
            row.setRoleId(write.roleId());
            row.setPermission(p.name());
            grants.save(row);
        }
        LOG.debug("Set {} admin permission(s) on role {} in {}", requested.size(), write.roleId(), write.realmId());
        return new AdminRoleGrantsDto(write.realmId(), write.roleId(), role.get().getName(),
                requested.stream().map(AdminPermission::key).toList());
    }

    /**
     * Resolves the effective admin-permission keys for a principal holding {@code roleNames} in the realm.
     * <p>
     * Default-safe contract: if the realm has NO grants configured at all, returns {@code modelConfigured=false}
     * with an empty list — the {@code AdminAuthorizationManager} treats that as "allow" (today's behaviour).
     * A {@link AdminPermission#REALM_ADMIN} grant is expanded to every permission key.
     */
    public AdminEffectivePermissionsDto effectivePermissions(final String realmId, final List<String> roleNames) {
        if (grants.countByRealmId(realmId) == 0) {
            return new AdminEffectivePermissionsDto(realmId, false, List.of());
        }
        // The authenticated principal's authorities are the tenant-qualified role names (name + "_" + realmId,
        // e.g. "admin_master" — see UserService), but callers/tests may pass the bare role name. Match either so
        // the model actually resolves once a realm is configured (otherwise a configured realm 403s the admin).
        final List<String> names = roleNames == null ? List.<String>of() : roleNames;
        final List<String> roleIds = names.isEmpty() ? List.<String>of()
                : userRolesRepository.findAllByTenantId(realmId).stream()
                        .filter(r -> names.contains(r.getName()) || names.contains(r.getTenantRoleName()))
                        .map(UserRoles::getRoleId).toList();

        final Set<AdminPermission> effective = new LinkedHashSet<>();
        if (!roleIds.isEmpty()) {
            grants.findAllByRealmIdAndRoleIdIn(realmId, roleIds).forEach(g ->
                    AdminPermission.from(g.getPermission()).ifPresent(effective::add));
        }
        if (effective.contains(AdminPermission.REALM_ADMIN)) {
            return new AdminEffectivePermissionsDto(realmId, true,
                    Arrays.stream(AdminPermission.values()).map(AdminPermission::key).toList());
        }
        final List<String> keys = new ArrayList<>(effective.stream().map(AdminPermission::key).toList());
        return new AdminEffectivePermissionsDto(realmId, true, keys);
    }
}
