/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.role;

import io.helixiam.authorization.domain.role.admin.RoleDto;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserInRole;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Helix IAM E8.5-S2: realm role administration + assignment. Roles are tenant(realm)-scoped rows in
 * {@code user_roles}; a user holds a role through {@code user_in_role} keyed by the user's tenant link.
 * This is the persistence side of the console's Realm roles screen and the per-user role manager.
 */
@Service
public class RoleAdminService {

    private static final Logger LOG = LogManager.getLogger(RoleAdminService.class);

    private final UserRolesRepository userRolesRepository;
    private final UserInRoleRepository userInRoleRepository;
    private final TenantUserRepository tenantUserRepository;

    @Autowired
    public RoleAdminService(final UserRolesRepository userRolesRepository,
                            final UserInRoleRepository userInRoleRepository,
                            final TenantUserRepository tenantUserRepository) {
        this.userRolesRepository = userRolesRepository;
        this.userInRoleRepository = userInRoleRepository;
        this.tenantUserRepository = tenantUserRepository;
    }

    /** Every role defined in the realm. */
    public List<RoleDto> list(final String realmId) {
        return userRolesRepository.findAllByTenantId(realmId).stream().map(r -> toDto(realmId, r)).toList();
    }

    /** Creates a realm role; idempotent — returns the existing role if the name is already taken. */
    @Transactional
    public RoleDto create(final String realmId, final String name) {
        // Invariant guard: a role must have a name.
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Role name is required.");
        }
        if (userRolesRepository.existsByTenantIdAndName(realmId, name)) {
            return userRolesRepository.findByTenantIdAndName(realmId, name).map(r -> toDto(realmId, r)).orElse(null);
        }
        final UserRoles saved = userRolesRepository.save(new UserRoles(name, realmId));
        LOG.debug("Created realm role {} in {}", name, realmId);
        return toDto(realmId, saved);
    }

    /**
     * Removes a realm role (and every assignment of it); {@code false} if it isn't in this realm or is a
     * protected system role (the controller rejects a system-role delete with a 400 before reaching here;
     * the check is repeated as a safety net for any non-console caller).
     */
    @Transactional
    public boolean delete(final String realmId, final String roleId) {
        final Optional<UserRoles> role = userRolesRepository.findById(roleId);
        if (role.isEmpty() || !realmId.equals(role.get().getTenantId()) || role.get().isSystemRole()) {
            return false;
        }
        userInRoleRepository.deleteAll(userInRoleRepository.findAllByRoleId(roleId));
        userRolesRepository.delete(role.get());
        LOG.debug("Deleted realm role {} from {}", roleId, realmId);
        return true;
    }

    /**
     * Designates {@code roleId} as the realm's default role (auto-assigned to new users), clearing any prior
     * default so at most one exists. Returns the updated role, or {@code null} if it isn't in this realm.
     */
    @Transactional
    public RoleDto setDefault(final String realmId, final String roleId) {
        final Optional<UserRoles> target = userRolesRepository.findById(roleId);
        if (target.isEmpty() || !realmId.equals(target.get().getTenantId())) {
            return null;
        }
        userRolesRepository.findAllByTenantIdAndDefaultRoleTrue(realmId).forEach(r -> {
            if (!r.getRoleId().equals(roleId) && r.isDefaultRole()) {
                r.setDefaultRole(false);
                userRolesRepository.save(r);
            }
        });
        final UserRoles role = target.get();
        if (!role.isDefaultRole()) {
            role.setDefaultRole(true);
            userRolesRepository.save(role);
        }
        LOG.debug("Set default role {} in realm {}", roleId, realmId);
        return toDto(realmId, role);
    }

    /** The realm roles assigned to a user. */
    public List<RoleDto> userRoles(final String realmId, final String userId) {
        return tenantUserRepository.findByTenantIdAndUserId(realmId, userId)
                .map(link -> link.getRoles().stream()
                        .filter(r -> realmId.equals(r.getTenantId()))
                        .map(r -> toDto(realmId, r)).toList())
                .orElse(List.of());
    }

    /** Grants a role to a user; {@code false} if the user is not a member of the realm. */
    @Transactional
    public boolean assign(final String realmId, final String userId, final String roleId) {
        final Optional<TenantUser> link = tenantUserRepository.findByTenantIdAndUserId(realmId, userId);
        if (link.isEmpty()) {
            return false;
        }
        if (userInRoleRepository.findByRoleIdAndUserId(roleId, userId).isEmpty()) {
            userInRoleRepository.save(new UserInRole(roleId, userId, link.get().getTenantUserId()));
            LOG.debug("Assigned role {} to user {} in {}", roleId, userId, realmId);
        }
        return true;
    }

    /** Revokes a role from a user; {@code false} if it wasn't assigned. */
    @Transactional
    public boolean unassign(final String realmId, final String userId, final String roleId) {
        return userInRoleRepository.findByRoleIdAndUserId(roleId, userId).map(uir -> {
            userInRoleRepository.delete(uir);
            LOG.debug("Revoked role {} from user {} in {}", roleId, userId, realmId);
            return true;
        }).orElse(false);
    }

    private RoleDto toDto(final String realmId, final UserRoles role) {
        return new RoleDto(realmId, role.getRoleId(), role.getName(), role.isSystemRole(), role.isDefaultRole());
    }
}
