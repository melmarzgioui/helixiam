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
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

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
 * <p>Callers are the explicitly declared {@link AdminActor} — never inferred from the request: an admin (declared
 * where the admin route is authorised), an unprivileged machine (SCIM, DCR), self-service, or {@link AdminActor#asSystem}
 * internal work. Without an actor, anything conferring admin permissions is refused.
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

    public AdminGrantGuard(final UserRolesRepository roles, final AdminRolePermissionRepository grants,
                           final UserGroupRoleRepository groupRoles) {
        this.roles = roles;
        this.grants = grants;
        this.groupRoles = groupRoles;
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
        final Set<String> held = callerPermissions(realmId, what);
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
     * The acting principal's admin permissions in {@code realmId}, from the explicitly declared {@link AdminActor}
     * (never inferred from the request URI): {@code null} for unrestricted ({@link AdminActor#asSystem} or dev-open),
     * an empty set for an unprivileged machine caller or self-service, the principal's permissions for an admin.
     *
     * @throws AdminGrantDeniedException no actor was declared — refused, nothing is exempt by default
     */
    public Set<String> callerPermissions(final String realmId, final String what) {
        final AdminActor actor = AdminActor.current().orElseThrow(() -> new AdminGrantDeniedException(
                what + " needs an acting administrator, and none was declared; refused."));
        return switch (actor.kind()) {
            case SYSTEM, DEV_OPEN -> null;
            case UNPRIVILEGED, SELF -> Set.of();
            case ADMIN -> permissionsOf(actor.authentication(), realmId);
        };
    }

    private Set<String> permissionsOf(final Authentication auth, final String realmId) {
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            return Set.of();
        }
        return permissionsOfAuthorities(SignInAuthorities.roleNames(auth), realmId);
    }

    /**
     * The admin permissions a principal with these role authorities ({@code <role>_<realm>}, across every realm it
     * belongs to) holds in {@code realmId} — exactly as {@code AdminAuthorizationManager} decides: {@code admin_master}
     * (the master realm administers every realm) or {@code admin_<realmId>} is realm-admin; otherwise the admin-RBAC
     * grants of the realm's roles the authorities name.
     */
    public Set<String> permissionsOfAuthorities(final List<String> names, final String realmId) {
        final String master = "admin_" + io.helixiam.authorization.domain.realm.RealmConfig.ADMIN_REALM_ID;
        if (names.contains(master) || names.contains("admin_" + realmId)) {
            return Set.of(AdminPermission.REALM_ADMIN.key());
        }
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
