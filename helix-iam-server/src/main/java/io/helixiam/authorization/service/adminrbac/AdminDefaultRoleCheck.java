/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.adminrbac;

import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Security review (rc.11): a default role that carries admin permissions would make every new user an
 * administrator. Such roles can no longer be created, but older data may hold one: at start-up each is reported with
 * a WARN and a {@code DEFAULT_ROLE_HAS_ADMIN_PERMISSIONS} audit event. The data is not changed; new users are simply
 * not given that role ({@code DefaultRoleAssignmentService}) until an admin picks another default role or removes the
 * grants.
 */
@Component
public class AdminDefaultRoleCheck implements ApplicationRunner {

    private static final Logger LOG = LogManager.getLogger(AdminDefaultRoleCheck.class);

    private final UserRolesRepository roles;
    private final AdminGrantGuard guard;
    private final AuditLog audit;

    public AdminDefaultRoleCheck(final UserRolesRepository roles, final AdminGrantGuard guard, final AuditLog audit) {
        this.roles = roles;
        this.guard = guard;
        this.audit = audit;
    }

    @Override
    public void run(final ApplicationArguments args) {
        check();
    }

    /** Reports (and returns) the default roles that carry admin permissions. */
    public List<UserRoles> check() {
        final List<UserRoles> found = new ArrayList<>();
        for (final UserRoles role : roles.findAll()) {
            if (!role.isDefaultRole() || role.getTenantId() == null) {
                continue;
            }
            final Set<String> grants = guard.grantsOf(role.getTenantId(), role.getRoleId());
            if (grants.isEmpty()) {
                continue;
            }
            found.add(role);
            LOG.warn("Realm {}: the default role '{}' carries admin permissions {}; new users are not given it. "
                            + "Choose another default role or remove the grants.", LogSafe.sanitize(role.getTenantId()),
                    LogSafe.sanitize(role.getName()), grants);
            audit.emit(AuditEvent.admin(AuditContext.nowIso(), "DEFAULT_ROLE_HAS_ADMIN_PERMISSIONS", role.getTenantId(),
                    "system", null, "role", role.getRoleId(), "FAILURE",
                    Map.of("role", role.getName(), "permissions", String.join(",", grants))));
        }
        return found;
    }
}
