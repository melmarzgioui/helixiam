/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.tenant.Tenant;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserInRole;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.client.ConsoleClientBootstrapService;
import io.helixiam.authorization.service.role.DefaultRoles;
import io.helixiam.authorization.service.role.DefaultRolesBootstrapService;
import io.helixiam.common.security.SecurityContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service responsible for handling Tenant logic.
 *
 * Validates CRUD tenant and users in tenant
 */
@Service
public class TenantService {

    private static final Logger LOG = LogManager.getLogger(TenantService.class);

    private final TenantRepository tenantRepository;
    private final UserRolesRepository userRolesRepository;
    private final UserInRoleRepository userInRoleRepository;
    private final TenantUserRepository tenantUserRepository;
    private final RealmService realmService;
    private final DefaultRolesBootstrapService defaultRolesBootstrapService;
    private final ConsoleClientBootstrapService consoleClientBootstrapService;

    @Autowired
    public TenantService(
            final TenantRepository tenantRepository,
            final UserRolesRepository userRolesRepository,
            final UserInRoleRepository userInRoleRepository,
            final TenantUserRepository tenantUserRepository,
            final RealmService realmService,
            final DefaultRolesBootstrapService defaultRolesBootstrapService,
            final ConsoleClientBootstrapService consoleClientBootstrapService
    ) {
        this.tenantRepository = tenantRepository;
        this.userRolesRepository = userRolesRepository;
        this.userInRoleRepository = userInRoleRepository;
        this.tenantUserRepository = tenantUserRepository;
        this.realmService = realmService;
        this.defaultRolesBootstrapService = defaultRolesBootstrapService;
        this.consoleClientBootstrapService = consoleClientBootstrapService;
    }

    /**
     * Create a new tenant and assign default roles (ADMIN, USER) to the creator.
     */
    public Boolean create(final String tenantId, final String tenantName) {
        if (tenantRepository.findById(tenantId).isEmpty()) {
            final String userId = SecurityContext.getUserId();

            // Create tenant
            final Tenant tenant = new Tenant();
            tenant.setTenantId(tenantId);
            tenant.setName(tenantName);
            tenantRepository.save(tenant);

            // A realm maps 1:1 to a tenant; seed its config with platform defaults (E1.3).
            realmService.createIfAbsent(tenantId, tenantName);

            // Seed the curated default roles (admin/user/auditor + admin-permission grants) — the same
            // Keycloak/WSO2-class set every realm gets, so a tenant-created realm is consistent with the rest.
            defaultRolesBootstrapService.ensureDefaultRoles(tenantId);
            // Seed the standard helix-console OIDC client so this realm's admins can log into the console via SSO.
            consoleClientBootstrapService.ensureConsoleClient(tenantId);

            LOG.debug("Created tenant {} by {}", tenant, userId);

            // Assign user to tenant
            final TenantUser tenantUser = new TenantUser();
            tenantUser.setUserId(userId);
            tenantUser.setTenantId(tenantId);
            final TenantUser storedTenantUser = tenantUserRepository.save(tenantUser);

            // Legacy platform roles kept for back-compat with the tenant-admin @PreAuthorize guards below.
            final UserRoles newUserRole = userRolesRepository.save(new UserRoles("ROLE_USER", tenantId));
            final UserRoles newAdminRole = userRolesRepository.save(new UserRoles("ROLE_ADMIN", tenantId));
            grant(newAdminRole.getRoleId(), userId, storedTenantUser.getTenantUserId());
            grant(newUserRole.getRoleId(), userId, storedTenantUser.getTenantUserId());

            // Assign the creator the curated admin + user roles so they have real console admin (realm-admin).
            userRolesRepository.findByTenantIdAndName(tenantId, DefaultRoles.ADMIN)
                    .ifPresent(r -> grant(r.getRoleId(), userId, storedTenantUser.getTenantUserId()));
            userRolesRepository.findByTenantIdAndName(tenantId, DefaultRoles.USER)
                    .ifPresent(r -> grant(r.getRoleId(), userId, storedTenantUser.getTenantUserId()));
        }

        return true;
    }

    /**
     * Persist a list of user roles.
     */
    public void save(final List<UserRoles> roles) {
        userRolesRepository.saveAll(roles);
    }

    /**
     * Save a tenant user and assign the realm's default role (the curated {@code user} role, falling back to
     * the legacy {@code ROLE_USER}) if not already present.
     */
    public void save(final TenantUser tenantUser) {
        if (tenantUserRepository.findByTenantIdAndUserId(tenantUser.getTenantId(), tenantUser.getUserId()).isEmpty()) {
            final TenantUser storedTenantUser = tenantUserRepository.save(tenantUser);

            userRolesRepository.findFirstByTenantIdAndDefaultRoleTrue(tenantUser.getTenantId())
                    .or(() -> userRolesRepository.findByTenantIdAndName(tenantUser.getTenantId(), "ROLE_USER"))
                    .ifPresent(role -> grant(role.getRoleId(), tenantUser.getUserId(), storedTenantUser.getTenantUserId()));
        }
    }

    /** Idempotently grants a role to a user via their tenant-user link. */
    private void grant(final String roleId, final String userId, final String tenantUserId) {
        if (userInRoleRepository.findByRoleIdAndUserIdAndTenantUserId(roleId, userId, tenantUserId).isEmpty()) {
            userInRoleRepository.save(new UserInRole(roleId, userId, tenantUserId));
        }
    }

    /**
     * Delete a tenant member (not allowed to delete self).
     */
    public void deleteTenantMember(final String tenantId, final String userId) {
        if (userId != null && !userId.equals(SecurityContext.getUserId())) {
            tenantUserRepository.findByTenantIdAndUserId(tenantId, userId).ifPresent(tenantUserRepository::delete);
        }
    }

    /**
     * Get all users associated with a tenant.
     */
    public List<TenantUser> getTenantMember(final String tenantId) {
        return tenantUserRepository.findAllByTenantId(tenantId);
    }

    /**
     * Get all tenants linked to the current user.
     */
    public List<TenantUser> me(final String userId) {
        return tenantUserRepository.findAllByUserId(userId);
    }

    /**
     * Assign user to a role (ADMIN restricted).
     */
    @PreAuthorize("hasRole('ROLE_ADMIN_'+#role.tenantId)")
    public Boolean assignUserToTRole(final UserRoles role, final String userId) {
        userRolesRepository.findByTenantIdAndName(role.getTenantId(), role.getName()).ifPresent(userRoles ->
                tenantUserRepository.findByTenantIdAndUserId(role.getTenantId(), userId).ifPresent(tenantUser -> {
                    if (userInRoleRepository.findByRoleIdAndUserIdAndTenantUserId(userRoles.getRoleId(), userId, tenantUser.getTenantUserId()).isEmpty()) {
                        final UserInRole userInRole = new UserInRole(userRoles.getRoleId(), tenantUser.getUserId(), tenantUser.getTenantUserId());
                        userInRoleRepository.save(userInRole);
                    }
                })
        );

        return true;
    }

    /**
     * Revoke a user from a role (ADMIN restricted).
     */
    @PreAuthorize("hasRole('ROLE_ADMIN_'+#role.tenantId)")
    public Boolean revokeUserToTRole(final UserRoles role, final String userId) {
        userRolesRepository.findByTenantIdAndName(role.getTenantId(), role.getName())
                .flatMap(userRoles -> userInRoleRepository.findByRoleIdAndUserId(userRoles.getRoleId(), userId))
                .ifPresent(userInRoleRepository::delete);

        return true;
    }
}
