package group.mfnr.authorization.service.user;

import group.mfnr.authorization.domain.tenant.Tenant;
import group.mfnr.authorization.domain.tenant.TenantUser;
import group.mfnr.authorization.domain.user.UserCredentials;
import group.mfnr.authorization.domain.user.UserRoles;
import group.mfnr.authorization.domain.user.admin.UserAdminDto;
import group.mfnr.authorization.domain.user.admin.UserChangePasswordDto;
import group.mfnr.authorization.domain.user.admin.UserPasswordDto;
import group.mfnr.authorization.domain.user.admin.UserWriteDto;
import group.mfnr.authorization.repository.UserCredentialsRepository;
import group.mfnr.authorization.repository.tenant.TenantRepository;
import group.mfnr.authorization.repository.tenant.TenantUserRepository;
import group.mfnr.authorization.service.PasswordEncoderService;
import group.mfnr.authorization.service.role.DefaultRoleAssignmentService;
import group.mfnr.authorization.service.security.PasswordPolicyEnforcer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Helix IAM E8.5: realm-scoped user administration for the admin console. Users live in the global
 * {@code user_credentials} store and are bound to a realm through {@code tenant_user} (realmId ==
 * tenantId); roles are resolved from that link. Passwords are always Argon2id-encoded — never stored
 * raw and never returned. This is the persistence side of the console's Users screen.
 */
@Service
public class UserAdminService {

    private static final Logger LOG = LogManager.getLogger(UserAdminService.class);

    private final TenantUserRepository tenantUserRepository;
    private final TenantRepository tenantRepository;
    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoderService passwordEncoderService;

    // Auth-hardening (features 3+4): password-policy/HIBP/history enforcement. Field-injected so this
    // service's constructor signature (and its existing tests) are untouched; optional so a unit test that
    // builds the service via the constructor without a Spring context simply skips enforcement.
    @Autowired(required = false)
    private PasswordPolicyEnforcer passwordPolicyEnforcer;

    // Curated default roles: a newly-created realm user auto-receives the realm's default role (the seeded
    // {@code user} role). Field-injected + optional so the existing constructor + its unit tests are untouched.
    @Autowired(required = false)
    private DefaultRoleAssignmentService defaultRoleAssignmentService;

    // NHI governance: when a human is disabled/deleted, cascade-suspend the agents they own so no orphaned
    // (ownerless) non-human identity is left running. Optional so the constructor + existing tests are untouched.
    @Autowired(required = false)
    private group.mfnr.authorization.service.agent.AgentOwnerReviewService agentOwnerReviewService;

    @Autowired
    public UserAdminService(final TenantUserRepository tenantUserRepository,
                            final TenantRepository tenantRepository,
                            final UserCredentialsRepository userCredentialsRepository,
                            final PasswordEncoderService passwordEncoderService) {
        this.tenantUserRepository = tenantUserRepository;
        this.tenantRepository = tenantRepository;
        this.userCredentialsRepository = userCredentialsRepository;
        this.passwordEncoderService = passwordEncoderService;
    }

    /** Every user bound to {@code realmId}, with roles + attributes resolved from the tenant link. */
    public List<UserAdminDto> list(final String realmId) {
        return tenantUserRepository.findAllByTenantId(realmId).stream()
                .map(link -> userCredentialsRepository.findByUserId(link.getUserId())
                        .map(user -> toDto(realmId, user, link))
                        .orElse(null))
                .filter(Objects::nonNull)
                .toList();
    }

    /** A single realm user, when both the tenant link and the credential exist. */
    public Optional<UserAdminDto> get(final String realmId, final String userId) {
        return tenantUserRepository.findByTenantIdAndUserId(realmId, userId)
                .flatMap(link -> userCredentialsRepository.findByUserId(userId)
                        .map(user -> toDto(realmId, user, link)));
    }

    /** Creates a realm user: a global credential (Argon2id) plus a tenant link binding it to the realm. */
    @Transactional
    public UserAdminDto create(final UserWriteDto write) {
        // Invariant guard: a malformed AMQP message must not persist a user without a username/password.
        if (write.username() == null || write.username().isBlank()) {
            throw new IllegalArgumentException("Username is required.");
        }
        // A password is optional: realm config-as-code import carries profiles, never credentials. When
        // absent we create a credential-less account and force UPDATE_PASSWORD before the first login,
        // rather than rejecting the import (B1 required-actions). Interactive admin create should still
        // supply one — the console form validates that client-side.
        final boolean hasPassword = write.password() != null && !write.password().isBlank();
        final UserCredentials user = new UserCredentials();
        user.setUsername(write.username() == null ? null : write.username().toLowerCase());
        user.setEmail(normaliseEmail(write.email()));
        String encoded = null;
        if (hasPassword) {
            // Auth-hardening: enforce the realm's password policy (length/character class/not-username/HIBP).
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.enforce(write.realmId(), null, write.username(), write.password());
            }
            encoded = passwordEncoderService.encode(write.password());
            user.setPassword(encoded);
            user.setPasswordSaltValue(null);
        } else {
            user.setRequiredActions("UPDATE_PASSWORD");
        }
        user.setDisabled(!write.enabled());
        user.setAccountLocked(write.locked());
        if (write.attributes() != null) {
            user.getUserAttributes().putAll(write.attributes());
        }
        final UserCredentials saved = userCredentialsRepository.save(user);
        if (hasPassword && passwordPolicyEnforcer != null) {
            passwordPolicyEnforcer.recordHistory(write.realmId(), saved.getUserId(), encoded);
        }

        ensureTenant(write.realmId());
        final TenantUser link = new TenantUser();
        link.setTenantId(write.realmId());
        link.setUserId(saved.getUserId());
        final TenantUser savedLink = tenantUserRepository.save(link);

        // Curated default roles: grant the realm's default role (e.g. 'user') to the new account.
        if (defaultRoleAssignmentService != null) {
            defaultRoleAssignmentService.assignDefaultRole(write.realmId(), saved.getUserId(), savedLink.getTenantUserId());
        }

        LOG.debug("Created user {} in realm {}", saved.getUsername(), write.realmId());
        return toDto(write.realmId(), saved, savedLink);
    }

    /** Updates the enabled/locked flags and (when supplied) replaces the attribute set. */
    @Transactional
    public Optional<UserAdminDto> update(final UserWriteDto write) {
        return userCredentialsRepository.findByUserId(write.userId()).map(user -> {
            user.setDisabled(!write.enabled());
            user.setAccountLocked(write.locked());
            user.setEmail(normaliseEmail(write.email()));
            if (write.attributes() != null) {
                user.getUserAttributes().clear();
                user.getUserAttributes().putAll(write.attributes());
            }
            final UserCredentials saved = userCredentialsRepository.save(user);
            // Deprovisioning cascade: disabling a user auto-suspends the agents they own (no ownerless NHIs).
            if (!write.enabled() && agentOwnerReviewService != null) {
                agentOwnerReviewService.cascadeOnDeprovision(write.realmId(), saved.getUsername(), saved.getEmail());
            }
            final TenantUser link = tenantUserRepository
                    .findByTenantIdAndUserId(write.realmId(), write.userId()).orElse(null);
            return toDto(write.realmId(), saved, link);
        });
    }

    /** Sets a new Argon2id password for a user; {@code false} if the user does not exist. */
    @Transactional
    public boolean resetPassword(final UserPasswordDto reset) {
        if (reset.newPassword() == null || reset.newPassword().isBlank()) {
            throw new IllegalArgumentException("New password is required.");
        }
        return userCredentialsRepository.findByUserId(reset.userId()).map(user -> {
            // Auth-hardening: enforce the realm's password policy on reset too.
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.enforce(reset.realmId(), reset.userId(), user.getUsername(), reset.newPassword());
            }
            final String encoded = passwordEncoderService.encode(reset.newPassword());
            user.setPassword(encoded);
            user.setPasswordSaltValue(null);
            userCredentialsRepository.save(user);
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.recordHistory(reset.realmId(), reset.userId(), encoded);
            }
            LOG.debug("Reset password for user {} in realm {}", reset.userId(), reset.realmId());
            return true;
        }).orElse(false);
    }

    /**
     * Self-service password change (6): verifies the user's <em>current</em> password before setting the
     * new one. Returns {@code false} when the user does not exist or the current password does not match,
     * so a caller can never set a new password without proving knowledge of the old one. The new password
     * is Argon2id-encoded; the legacy salt column is cleared (the verify also transparently upgrades a
     * legacy-hashed credential, since it is re-encoded here regardless).
     */
    @Transactional
    public boolean changePassword(final UserChangePasswordDto change) {
        if (change.newPassword() == null || change.newPassword().isBlank()) {
            throw new IllegalArgumentException("New password is required.");
        }
        return userCredentialsRepository.findByUserId(change.userId()).map(user -> {
            if (!passwordEncoderService.matches(change.currentPassword(), user.getPassword(),
                    user.getPasswordSaltValue())) {
                LOG.debug("Self password change rejected for user {} — current password mismatch", change.userId());
                return false;
            }
            // Auth-hardening: the self-service change is held to the same realm password policy as create/reset.
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.enforce(change.realmId(), change.userId(), user.getUsername(), change.newPassword());
            }
            final String encoded = passwordEncoderService.encode(change.newPassword());
            user.setPassword(encoded);
            user.setPasswordSaltValue(null);
            userCredentialsRepository.save(user);
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.recordHistory(change.realmId(), change.userId(), encoded);
            }
            LOG.debug("User {} changed their own password in realm {}", change.userId(), change.realmId());
            return true;
        }).orElse(false);
    }

    /**
     * Unbinds a user from a realm (removes the tenant link); when that was the user's last realm the
     * global credential is deleted too. {@code false} if the user was not in the realm.
     */
    @Transactional
    public boolean delete(final String realmId, final String userId) {
        final Optional<TenantUser> link = tenantUserRepository.findByTenantIdAndUserId(realmId, userId);
        if (link.isEmpty()) {
            return false;
        }
        // Deprovisioning cascade: removing a user from a realm auto-suspends the agents they owned there.
        if (agentOwnerReviewService != null) {
            userCredentialsRepository.findByUserId(userId).ifPresent(u ->
                    agentOwnerReviewService.cascadeOnDeprovision(realmId, u.getUsername(), u.getEmail()));
        }
        tenantUserRepository.delete(link.get());
        if (tenantUserRepository.findAllByUserId(userId).isEmpty()) {
            userCredentialsRepository.findByUserId(userId).ifPresent(userCredentialsRepository::delete);
        }
        LOG.debug("Removed user {} from realm {}", userId, realmId);
        return true;
    }

    /** B1: set (replace) a user's required-actions CSV; {@code false} if the user does not exist. */
    @Transactional
    public boolean setRequiredActions(final String userId, final String requiredActionsCsv) {
        return userCredentialsRepository.findByUserId(userId).map(user -> {
            user.setRequiredActions(requiredActionsCsv == null || requiredActionsCsv.isBlank() ? null : requiredActionsCsv.trim());
            userCredentialsRepository.save(user);
            LOG.debug("Set required actions [{}] for user {}", requiredActionsCsv, userId);
            return true;
        }).orElse(false);
    }

    /** B1: the user's pending required-actions CSV ({@code null}/blank = none). */
    public String getRequiredActions(final String userId) {
        return userCredentialsRepository.findByUserId(userId).map(UserCredentials::getRequiredActions).orElse(null);
    }

    /** B1: remove one completed action from the user's CSV; returns the remaining CSV (may be blank). */
    @Transactional
    public String clearRequiredAction(final String userId, final String action) {
        return userCredentialsRepository.findByUserId(userId).map(user -> {
            final String remaining = java.util.Arrays.stream((user.getRequiredActions() == null ? "" : user.getRequiredActions()).split(","))
                    .map(String::trim).filter(s -> !s.isEmpty() && !s.equalsIgnoreCase(action))
                    .collect(java.util.stream.Collectors.joining(","));
            user.setRequiredActions(remaining.isBlank() ? null : remaining);
            userCredentialsRepository.save(user);
            return remaining;
        }).orElse("");
    }

    /** A user's realm link FKs to {@code tenant}; a realm may exist only as config, so back-fill it. */
    private void ensureTenant(final String realmId) {
        if (tenantRepository.findById(realmId).isEmpty()) {
            final Tenant tenant = new Tenant();
            tenant.setTenantId(realmId);
            tenant.setName(realmId);
            tenantRepository.save(tenant);
        }
    }

    private UserAdminDto toDto(final String realmId, final UserCredentials user, final TenantUser link) {
        final List<String> roles = link == null ? List.of()
                : link.getRoles().stream().map(UserRoles::getName).filter(Objects::nonNull).sorted().toList();
        final Map<String, String> attributes = user.getUserAttributes() == null ? Map.of() : user.getUserAttributes();
        final Long createdAt = user.getCreationDate() == null ? null : user.getCreationDate().getTime();
        return new UserAdminDto(realmId, user.getUserId(), user.getUsername(), user.getEmail(), !user.isDisabled(),
                user.isLocked(), user.isMfaEnabled(), roles, attributes, createdAt);
    }

    /** Email is matched case-insensitively at login, so it is stored lowercase; blank means "none". */
    private static String normaliseEmail(final String email) {
        return email == null || email.isBlank() ? null : email.trim().toLowerCase();
    }
}
