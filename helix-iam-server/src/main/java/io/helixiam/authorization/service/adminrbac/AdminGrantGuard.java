/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.adminrbac;

import io.helixiam.authorization.domain.adminrbac.AdminPermission;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionRepository;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.repository.group.UserGroupRoleRepository;
import io.helixiam.authorization.security.SignInAuthorities;
import io.helixiam.authorization.security.adminrbac.RealmAdminAuthorities;
import io.helixiam.authorization.service.role.DefaultRoles;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Security review (found in rc.11): <b>an admin can never grant admin permissions they do not hold.</b>
 *
 * <p>A realm role confers admin permissions through its admin-RBAC grants, and the role named {@code admin} confers
 * {@code realm-admin} by its name alone ({@code admin_<realm>} authority). Assigning or unassigning such a role — to a
 * user, a group, a group member, a service account — is allowed only when the role's permissions are a subset of the
 * caller's own; a role conferring {@code realm-admin} always needs a caller holding {@code realm-admin}. Setting admin
 * grants needs {@code realm-admin}. A role with any admin permission cannot be the default role.
 *
 * <p>Callers: the authenticated principal of the current HTTP request (an admin session or an admin service
 * account). A request without an authenticated principal (SCIM, a federated login) holds no admin permission. Code
 * outside any request (start-up bootstrap) is the system and is not restricted. Dev-open admin mode is not restricted.
 */
@Component
public class AdminGrantGuard {

    /** Refused: the caller would grant admin permissions they do not hold (the API's 403). */
    public static class AdminGrantDeniedException extends RuntimeException {
        public AdminGrantDeniedException(final String message) {
            super(message);
        }
    }

    /** Refused: a role with admin permissions cannot be the realm's default role (the API's 400). */
    public static class AdminDefaultRoleException extends IllegalArgumentException {
        public AdminDefaultRoleException(final String message) {
            super(message);
        }
    }

    private final UserRolesRepository roles;
    private final AdminRolePermissionRepository grants;
    private final UserGroupRoleRepository groupRoles;
    private final boolean devOpen;

    public AdminGrantGuard(final UserRolesRepository roles, final AdminRolePermissionRepository grants,
                           final UserGroupRoleRepository groupRoles,
                           @Value("${helix.admin.dev-open:false}") final boolean devOpen) {
        this.roles = roles;
        this.grants = grants;
        this.groupRoles = groupRoles;
        this.devOpen = devOpen;
    }

    // ------------------------------------------------------------------------------------------------ what roles confer

    /** The admin permissions {@code roleId} confers in {@code realmId} (empty for an unknown or foreign role). */
    public Set<String> grantsOf(final String realmId, final String roleId) {
        final Optional<UserRoles> role = roleId == null ? Optional.empty() : roles.findById(roleId);
        if (role.isEmpty() || !realmId.equals(role.get().getTenantId())) {
            return Set.of();
        }
        return grantsOf(realmId, role.get());
    }

    private Set<String> grantsOf(final String realmId, final UserRoles role) {
        final Set<String> out = new LinkedHashSet<>();
        if (DefaultRoles.ADMIN.equals(role.getName())) {
            out.add(AdminPermission.REALM_ADMIN.key()); // admin_<realm>: realm admin by name
        }
        grants.findAllByRealmIdAndRoleId(realmId, role.getRoleId())
                .forEach(g -> AdminPermission.from(g.getPermission()).ifPresent(p -> out.add(p.key())));
        return out;
    }

    /** The admin permissions the realm role named {@code roleName} confers. */
    public Set<String> grantsOfName(final String realmId, final String roleName) {
        if (roleName == null) {
            return Set.of();
        }
        for (final UserRoles r : roles.findAllByTenantId(realmId)) {
            if (roleName.equals(r.getName()) || roleName.equals(r.getTenantRoleName())) {
                return grantsOf(realmId, r);
            }
        }
        return DefaultRoles.ADMIN.equals(roleName) ? Set.of(AdminPermission.REALM_ADMIN.key()) : Set.of();
    }

    /** The admin permissions a member of {@code groupId} gains through the group's roles. */
    public Set<String> grantsOfGroup(final String realmId, final String groupId) {
        final Set<String> out = new LinkedHashSet<>();
        groupRoles.findAllByGroupId(groupId).forEach(gr -> out.addAll(grantsOf(realmId, gr.getRoleId())));
        return out;
    }

    // ------------------------------------------------------------------------------------------------ checks

    /** Refuses unless the caller holds every permission in {@code conferred} (realm-admin for realm-admin). */
    public void requireMayGrant(final String realmId, final Collection<String> conferred, final String what) {
        if (conferred == null || conferred.isEmpty()) {
            return;
        }
        final Set<String> held = callerPermissions(realmId);
        if (held == null || held.contains(AdminPermission.REALM_ADMIN.key())) {
            return; // the system, dev-open, or a realm admin
        }
        if (conferred.contains(AdminPermission.REALM_ADMIN.key()) || !held.containsAll(conferred)) {
            throw new AdminGrantDeniedException(what + " confers admin permissions you do not hold ("
                    + String.join(", ", conferred) + "); ask a realm admin.");
        }
    }

    /** Refuses unless the caller holds realm-admin. */
    public void requireRealmAdmin(final String realmId, final String what) {
        requireMayGrant(realmId, List.of(AdminPermission.REALM_ADMIN.key()), what);
    }

    /** Refuses a default role that confers any admin permission. */
    public void requireNotAdminDefault(final String realmId, final String roleId) {
        if (!grantsOf(realmId, roleId).isEmpty()) {
            throw new AdminDefaultRoleException("A role with admin permissions cannot be the default role: every new "
                    + "user would become an administrator.");
        }
    }

    /**
     * The caller's admin permissions in {@code realmId}: {@code null} for "unrestricted" (no request — the system — or
     * dev-open), else the set (containing realm-admin for a realm or master admin).
     */
    Set<String> callerPermissions(final String realmId) {
        if (devOpen || RequestContextHolder.getRequestAttributes() == null) {
            return null;
        }
        final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return Set.of();
        }
        if (RealmAdminAuthorities.isAdminOf(auth, realmId)) {
            return Set.of(AdminPermission.REALM_ADMIN.key());
        }
        final List<String> names = SignInAuthorities.roleNames(auth);
        final List<String> roleIds = roles.findAllByTenantId(realmId).stream()
                .filter(r -> !SignInAuthorities.isFactorName(r.getName()))
                .filter(r -> names.contains(r.getName()) || names.contains(r.getTenantRoleName()))
                .map(UserRoles::getRoleId).toList();
        final Set<String> held = new LinkedHashSet<>();
        if (!roleIds.isEmpty()) {
            grants.findAllByRealmIdAndRoleIdIn(realmId, roleIds)
                    .forEach(g -> AdminPermission.from(g.getPermission()).ifPresent(p -> held.add(p.key())));
        }
        return held;
    }
}
