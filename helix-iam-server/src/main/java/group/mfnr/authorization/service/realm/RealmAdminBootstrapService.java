package group.mfnr.authorization.service.realm;

import group.mfnr.authorization.domain.realm.RealmConfig;
import group.mfnr.authorization.domain.tenant.Tenant;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.UserInRole;
import group.mfnr.authorization.domain.user.UserRoles;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.UserInRoleRepository;
import group.mfnr.authorization.repository.UserRolesRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.PasswordEncoderService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Helix IAM: guarantees every realm has an {@code admin} role and an admin user, so a fresh deployment or a
 * newly-created realm is never left without a way in. Idempotent — safe to call on every startup and on each
 * realm creation; it never resets an existing admin's password.
 *
 * <p>The bootstrap admin credentials come from config (env-overridable): {@code helix.admin.username}
 * (default {@code admin}, env {@code HELIX_ADMIN_USERNAME}) and {@code helix.admin.password} (default
 * {@code admin}, env {@code HELIX_ADMIN_PASSWORD}). Usernames are globally unique, so the master realm uses
 * the configured username verbatim and every other realm gets a realm-qualified {@code <username>-<realm>}.
 */
@Service
public class RealmAdminBootstrapService {

    private static final Logger LOG = LogManager.getLogger(RealmAdminBootstrapService.class);
    public static final String ADMIN_ROLE = "admin";

    private final TenantRepository tenantRepository;
    private final UserRolesRepository userRolesRepository;
    private final UserCredentialsRepository userCredentialsRepository;
    private final TenantUserRepository tenantUserRepository;
    private final UserInRoleRepository userInRoleRepository;
    private final PasswordEncoderService passwordEncoderService;
    private final String adminUsername;
    private final String adminPassword;

    @Autowired
    public RealmAdminBootstrapService(final TenantRepository tenantRepository,
                                      final UserRolesRepository userRolesRepository,
                                      final UserCredentialsRepository userCredentialsRepository,
                                      final TenantUserRepository tenantUserRepository,
                                      final UserInRoleRepository userInRoleRepository,
                                      final PasswordEncoderService passwordEncoderService,
                                      @Value("${helix.admin.username:admin}") final String adminUsername,
                                      @Value("${helix.admin.password:admin}") final String adminPassword) {
        this.tenantRepository = tenantRepository;
        this.userRolesRepository = userRolesRepository;
        this.userCredentialsRepository = userCredentialsRepository;
        this.tenantUserRepository = tenantUserRepository;
        this.userInRoleRepository = userInRoleRepository;
        this.passwordEncoderService = passwordEncoderService;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
    }

    /** The bootstrap admin username for a realm — verbatim for master, realm-qualified otherwise (usernames are global). */
    public String adminUsernameFor(final String realmId) {
        return RealmConfig.ADMIN_REALM_ID.equals(realmId) ? adminUsername : adminUsername + "-" + realmId;
    }

    /** Ensures the realm has an {@code admin} role and an admin user holding it. Idempotent; never resets a password. */
    @Transactional
    public void ensureRealmAdmin(final String realmId) {
        ensureTenant(realmId);
        final UserRoles role = userRolesRepository.findByTenantIdAndName(realmId, ADMIN_ROLE)
                .orElseGet(() -> userRolesRepository.save(new UserRoles(ADMIN_ROLE, realmId)));

        final String username = adminUsernameFor(realmId).toLowerCase();
        final UserCredentials admin = userCredentialsRepository.findByUsername(username).orElseGet(() -> {
            final UserCredentials u = new UserCredentials();
            u.setUsername(username);
            u.setPassword(passwordEncoderService.encode(adminPassword));
            u.setPasswordSaltValue(null);
            u.setDisabled(false);
            u.setAccountLocked(false);
            final UserCredentials saved = userCredentialsRepository.save(u);
            LOG.info("Bootstrapped admin user '{}' for realm '{}'", username, realmId);
            return saved;
        });

        final TenantUser link = tenantUserRepository.findByTenantIdAndUserId(realmId, admin.getUserId())
                .orElseGet(() -> {
                    final TenantUser l = new TenantUser();
                    l.setTenantId(realmId);
                    l.setUserId(admin.getUserId());
                    return tenantUserRepository.save(l);
                });

        if (userInRoleRepository.findByRoleIdAndUserId(role.getRoleId(), admin.getUserId()).isEmpty()) {
            userInRoleRepository.save(new UserInRole(role.getRoleId(), admin.getUserId(), link.getTenantUserId()));
            LOG.info("Granted '{}' role to admin user '{}' in realm '{}'", ADMIN_ROLE, username, realmId);
        }
    }

    private void ensureTenant(final String realmId) {
        if (tenantRepository.findById(realmId).isEmpty()) {
            final Tenant tenant = new Tenant();
            tenant.setTenantId(realmId);
            tenant.setName(realmId);
            tenantRepository.save(tenant);
        }
    }
}
