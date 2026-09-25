/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.realm;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.tenant.Tenant;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.domain.user.UserInRole;
import io.helixiam.authorization.domain.user.UserRoles;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.UserInRoleRepository;
import io.helixiam.authorization.repository.UserRolesRepository;
import io.helixiam.authorization.repository.tenant.TenantRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.PasswordEncoderService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Helix IAM: guarantees every realm has an {@code admin} role and an admin user, so a fresh deployment or a
 * newly-created realm is never left without a way in. Idempotent — safe to call on every startup and on each
 * realm creation; it never resets an existing admin's password.
 *
 * <p>The bootstrap admin username comes from config (env-overridable): {@code helix.admin.username}
 * (default {@code admin}, env {@code HELIX_ADMIN_USERNAME}). The password comes from
 * {@code helix.admin.password} (env {@code HELIX_ADMIN_PASSWORD}); when it is left unset, a strong random
 * password is generated once and logged (a fresh zero-config deployment stays usable but never ships a
 * known default such as {@code admin/admin}). Usernames are globally unique, so the master realm uses the
 * configured username verbatim and every other realm gets a realm-qualified {@code <username>-<realm>}.
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
    /** From config; blank means "generate a strong one-time password instead of shipping a known default". */
    private final String configuredPassword;
    /** Optional path (helix.admin.password-file) to write a generated password to, 0600, instead of logging it. */
    private final String passwordFilePath;
    private volatile String bootstrapPassword;

    @Autowired
    public RealmAdminBootstrapService(final TenantRepository tenantRepository,
                                      final UserRolesRepository userRolesRepository,
                                      final UserCredentialsRepository userCredentialsRepository,
                                      final TenantUserRepository tenantUserRepository,
                                      final UserInRoleRepository userInRoleRepository,
                                      final PasswordEncoderService passwordEncoderService,
                                      @Value("${helix.admin.username:admin}") final String adminUsername,
                                      @Value("${helix.admin.password:}") final String adminPassword,
                                      @Value("${helix.admin.password-file:}") final String passwordFilePath) {
        this.tenantRepository = tenantRepository;
        this.userRolesRepository = userRolesRepository;
        this.userCredentialsRepository = userCredentialsRepository;
        this.tenantUserRepository = tenantUserRepository;
        this.userInRoleRepository = userInRoleRepository;
        this.passwordEncoderService = passwordEncoderService;
        this.adminUsername = adminUsername;
        this.configuredPassword = adminPassword;
        this.passwordFilePath = passwordFilePath;
    }

    /** The bootstrap admin username for a realm — verbatim for master, realm-qualified otherwise (usernames are global). */
    public String adminUsernameFor(final String realmId) {
        return RealmConfig.ADMIN_REALM_ID.equals(realmId) ? adminUsername : adminUsername + "-" + realmId;
    }

    /**
     * The password to set when creating a NEW bootstrap admin. Uses {@code helix.admin.password} when set;
     * otherwise generates a strong random password ONCE (cached, reused across realms) and logs it, so a
     * zero-config deployment is usable without ever shipping a known default credential.
     */
    synchronized String resolveBootstrapPassword() {
        if (configuredPassword != null && !configuredPassword.isBlank()) {
            return configuredPassword;
        }
        if (bootstrapPassword == null) {
            bootstrapPassword = generateStrongPassword();
            // L6: when a password file is configured, write it there (0600) and log ONLY the path,
            // so the credential does not sit in the logs. Falls back to logging it if the write fails.
            final boolean wroteFile = passwordFilePath != null && !passwordFilePath.isBlank()
                    && writePasswordFile(passwordFilePath, bootstrapPassword);
            LOG.warn("=====================================================================");
            LOG.warn("No helix.admin.password (HELIX_ADMIN_PASSWORD) configured — generated a one-time");
            LOG.warn("bootstrap admin password.");
            if (wroteFile) {
                LOG.warn("Written (0600) to: {}", passwordFilePath);
            } else {
                LOG.warn("Password: {}", bootstrapPassword);
            }
            LOG.warn("Sign in, change it, and set HELIX_ADMIN_PASSWORD for future deployments.");
            LOG.warn("=====================================================================");
        }
        return bootstrapPassword;
    }

    /**
     * Write the password to {@code path} with owner-only (0600) permissions, created ATOMICALLY so the
     * credential is never even briefly world-readable. On any failure the (possibly partial) file is
     * removed so the password is never left readable on disk, and false is returned — the caller then
     * logs it as the documented fallback, so the credential lands in exactly one place, never both.
     */
    private static boolean writePasswordFile(final String path, final String password) {
        Path file = null;
        try {
            file = Path.of(path);
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.deleteIfExists(file);
            try {
                // POSIX: create with rw------- as a file attribute (no world-readable window).
                Files.createFile(file, PosixFilePermissions.asFileAttribute(
                        PosixFilePermissions.fromString("rw-------")));
            } catch (final UnsupportedOperationException nonPosix) {
                // Non-POSIX filesystem (e.g. Windows): create then best-effort owner-only via the File API.
                Files.createFile(file);
                final java.io.File f = file.toFile();
                f.setReadable(false, false);
                f.setReadable(true, true);
                f.setWritable(false, false);
                f.setWritable(true, true);
            }
            Files.writeString(file, password + System.lineSeparator(), StandardOpenOption.WRITE);
            return true;
        } catch (final Exception e) {
            if (file != null) {
                try {
                    Files.deleteIfExists(file); // never leave a partial credential file behind
                } catch (final Exception cleanup) {
                    LOG.warn("Could not remove a partial bootstrap admin password file {}: {}", path, cleanup.getMessage());
                }
            }
            LOG.warn("Could not write the bootstrap admin password file {}: {}", path, e.getMessage());
            return false;
        }
    }

    private static String generateStrongPassword() {
        final byte[] bytes = new byte[24];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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
            u.setPassword(passwordEncoderService.encode(resolveBootstrapPassword()));
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
