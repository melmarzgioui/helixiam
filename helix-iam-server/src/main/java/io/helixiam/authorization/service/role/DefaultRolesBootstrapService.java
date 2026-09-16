package io.helixiam.authorization.service.role;

import io.helixiam.authorization.domain.adminrbac.AdminPermission;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionEntity;
import io.helixiam.authorization.domain.adminrbac.AdminRolePermissionRepository;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserRolesRepository;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Helix IAM: seeds the curated {@link DefaultRoles default roles} (admin / user / auditor) into a realm, with
 * their admin-permission grants — the out-of-the-box, Keycloak/WSO2-class role set. Idempotent and safe to
 * call on every startup and on each realm creation: it never duplicates a role or grant and never resets one.
 *
 * <p>The curated roles are flagged {@code system} (protected from deletion) and {@code user} is flagged the
 * realm default (auto-assigned to new users). Seeding {@code admin → realm-admin} activates fine-grained admin
 * RBAC enforcement for the realm (before any grant exists the model is "unconfigured" / fail-open); the admin
 * user holds {@code admin} so it keeps full access.
 */
@Service
public class DefaultRolesBootstrapService {

    private static final Logger LOG = LogManager.getLogger(DefaultRolesBootstrapService.class);

    /** name → (is the realm default role, admin permissions granted). */
    private record Definition(String name, boolean isDefault, List<AdminPermission> grants) {
    }

    private static final List<Definition> DEFAULTS = List.of(
            new Definition(DefaultRoles.ADMIN, false, List.of(AdminPermission.REALM_ADMIN)),
            new Definition(DefaultRoles.USER, true, List.of()),
            new Definition(DefaultRoles.AUDITOR, false,
                    List.of(AdminPermission.VIEW_USERS, AdminPermission.VIEW_CLIENTS, AdminPermission.VIEW_EVENTS)));

    private final UserRolesRepository roles;
    private final AdminRolePermissionRepository grants;

    @Autowired
    public DefaultRolesBootstrapService(final UserRolesRepository roles,
                                        final AdminRolePermissionRepository grants) {
        this.roles = roles;
        this.grants = grants;
    }

    /** Ensures the realm has the curated default roles + their admin-permission grants. Idempotent. */
    @Transactional
    public void ensureDefaultRoles(final String realmId) {
        for (final Definition d : DEFAULTS) {
            final UserRoles role = roles.findByTenantIdAndName(realmId, d.name())
                    .map(existing -> upgradeFlags(existing, d))
                    .orElseGet(() -> {
                        final UserRoles created = roles.save(new UserRoles(d.name(), realmId, true, d.isDefault()));
                        LOG.info("Seeded default role '{}' in realm '{}'", d.name(), realmId);
                        return created;
                    });
            ensureGrants(realmId, role.getRoleId(), d.grants());
        }
    }

    /** Brings an already-present role up to the curated flags (system, and default for {@code user}). */
    private UserRoles upgradeFlags(final UserRoles role, final Definition d) {
        boolean changed = false;
        if (!role.isSystemRole()) {
            role.setSystemRole(true);
            changed = true;
        }
        if (d.isDefault() && !role.isDefaultRole()) {
            role.setDefaultRole(true);
            changed = true;
        }
        return changed ? roles.save(role) : role;
    }

    /** Adds any missing admin-permission grants for the role (never removes). */
    private void ensureGrants(final String realmId, final String roleId, final List<AdminPermission> permissions) {
        if (roleId == null || permissions.isEmpty()) {
            return;
        }
        final Set<String> existing = grants.findAllByRealmIdAndRoleId(realmId, roleId).stream()
                .map(AdminRolePermissionEntity::getPermission).collect(Collectors.toSet());
        for (final AdminPermission p : permissions) {
            if (!existing.contains(p.name())) {
                final AdminRolePermissionEntity grant = new AdminRolePermissionEntity();
                grant.setRealmId(realmId);
                grant.setRoleId(roleId);
                grant.setPermission(p.name());
                grants.save(grant);
                LOG.info("Granted admin permission '{}' to role '{}' in realm '{}'", p.key(), roleId, realmId);
            }
        }
    }
}
