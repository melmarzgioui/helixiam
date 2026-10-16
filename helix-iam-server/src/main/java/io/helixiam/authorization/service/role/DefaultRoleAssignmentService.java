/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.role;

import io.helixiam.authorization.domain.user.UserInRole;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Helix IAM: grants a newly-created realm user the realm's default role (the {@code user} role seeded by
 * {@link DefaultRolesBootstrapService}). Idempotent and a no-op when the realm has no default role designated,
 * so callers can invoke it unconditionally.
 */
@Service
public class DefaultRoleAssignmentService {

    private static final Logger LOG = LogManager.getLogger(DefaultRoleAssignmentService.class);

    private final UserRolesRepository roles;
    private final UserInRoleRepository userInRole;

    @Autowired
    public DefaultRoleAssignmentService(final UserRolesRepository roles, final UserInRoleRepository userInRole) {
        this.roles = roles;
        this.userInRole = userInRole;
    }

    /** Security review (rc.11): no admin may grant admin permissions they do not hold. */
    private io.helixiam.authorization.service.adminrbac.AdminGrantGuard adminGrantGuard;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAdminGrantGuard(final io.helixiam.authorization.service.adminrbac.AdminGrantGuard adminGrantGuard) {
        this.adminGrantGuard = adminGrantGuard;
    }

    /** Assigns the realm's default role to {@code userId} (via their {@code tenantUserId} link), if any. */
    @Transactional
    public void assignDefaultRole(final String realmId, final String userId, final String tenantUserId) {
        roles.findFirstByTenantIdAndDefaultRoleTrue(realmId).ifPresent(role -> {
            if (adminGrantGuard != null && !adminGrantGuard.grantsOf(realmId, role.getRoleId()).isEmpty()) {
                LOG.warn("Not assigning default role '{}' in realm {}: it carries admin permissions",
                        LogSafe.sanitize(role.getName()), LogSafe.sanitize(realmId));
                return;
            }
            if (userInRole.findByRoleIdAndUserIdAndTenantUserId(role.getRoleId(), userId, tenantUserId).isEmpty()) {
                userInRole.save(new UserInRole(role.getRoleId(), userId, tenantUserId));
                LOG.debug("Assigned default role '{}' to user {} in realm {}",
                        LogSafe.sanitize(role.getName()), LogSafe.sanitize(userId), LogSafe.sanitize(realmId));
            }
        });
    }
}
