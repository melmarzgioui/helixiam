package group.mfnr.authorization.service.role;

import group.mfnr.authorization.domain.user.UserInRole;
import group.mfnr.authorization.repository.UserInRoleRepository;
import group.mfnr.authorization.repository.UserRolesRepository;
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

    /** Assigns the realm's default role to {@code userId} (via their {@code tenantUserId} link), if any. */
    @Transactional
    public void assignDefaultRole(final String realmId, final String userId, final String tenantUserId) {
        roles.findFirstByTenantIdAndDefaultRoleTrue(realmId).ifPresent(role -> {
            if (userInRole.findByRoleIdAndUserIdAndTenantUserId(role.getRoleId(), userId, tenantUserId).isEmpty()) {
                userInRole.save(new UserInRole(role.getRoleId(), userId, tenantUserId));
                LOG.debug("Assigned default role '{}' to user {} in realm {}", role.getName(), userId, realmId);
            }
        });
    }
}
