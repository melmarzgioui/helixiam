/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.user.ChangePassword;
import io.helixiam.authorization.domain.user.MfaUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.domain.user.VerifyEmail;
import io.helixiam.authorization.repository.ChangePasswordRepository;
import io.helixiam.authorization.repository.MfaUserRepository;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.VerifyEmailRepository;
import io.helixiam.notification.annotation.Notification;
import io.helixiam.notification.annotation.NotificationEmail;
import io.helixiam.notification.annotation.NotificationMediaType;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.domain.NotificationRequest;
import io.helixiam.notification.repository.NotificationCodeRepository;
import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.service.security.PasswordPolicyEnforcer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Service responsible for handling user service logic.
 *
 * Validate adds delete and verifies users and claims
 */
@Service
public class UserService {

    private final UserCredentialsRepository userCredentialsRepository;
    private final ChangePasswordRepository changePasswordRepository;
    private final NotificationCodeRepository notificationCodeRepository;
    private final VerifyEmailRepository verifyEmailRepository;
    private final MfaUserRepository mfaUserRepository;
    private final Notifier notifier;
    private io.helixiam.authorization.messaging.email.JdbcBounceRecorder emailBounces;
    private PasswordResetMailer passwordResetMailer;

    /** Sends the reset email to the account's stored address. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPasswordResetMailer(final PasswordResetMailer passwordResetMailer) {
        this.passwordResetMailer = passwordResetMailer;
    }
    private io.helixiam.notification.NotificationCodePolicy codePolicy =
            io.helixiam.notification.NotificationCodePolicy.defaults();

    /** How long the emailed reset and sign-up codes work (defaults: 1 hour, 24 hours). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setCodePolicy(final io.helixiam.notification.NotificationCodePolicy codePolicy) {
        if (codePolicy != null) {
            this.codePolicy = codePolicy;
        }
    }

    /** Clears a bounced address when the user verifies it again (the signup verification code). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setEmailBounces(final io.helixiam.authorization.messaging.email.JdbcBounceRecorder emailBounces) {
        this.emailBounces = emailBounces;
    }
    private final PasswordEncoderService passwordEncoderService;

    // Auth-hardening (features 3+4): enforce the realm's password policy on the public self-service paths.
    // Field-injected + optional so the constructor (and existing UserService tests) are untouched, and the
    // public reset/signup paths (which carry no realm) fall back to the default-realm policy.
    @Autowired(required = false)
    private PasswordPolicyEnforcer passwordPolicyEnforcer;

    /**
     * Optional internal recipient for the "a new user registered" notification. Blank (the default) means
     * the notification is not sent — a deployment must opt in with {@code helix.notifications.registration-recipient}
     * (env {@code HELIX_NOTIFICATIONS_REGISTRATION_RECIPIENT}). Previously this was a hard-coded address.
     */
    @org.springframework.beans.factory.annotation.Value("${helix.notifications.registration-recipient:}")
    private String registrationNotificationRecipient;

    @Autowired
    public UserService(
            final UserCredentialsRepository userCredentialsRepository,
            final ChangePasswordRepository changePasswordRepository,
            final NotificationCodeRepository notificationCodeRepository,
            final VerifyEmailRepository verifyEmailRepository,
            final MfaUserRepository mfaUserRepository,
            final Notifier notifier,
            final PasswordEncoderService passwordEncoderService
    ) {
        this.userCredentialsRepository = userCredentialsRepository;
        this.changePasswordRepository = changePasswordRepository;
        this.notificationCodeRepository = notificationCodeRepository;
        this.verifyEmailRepository = verifyEmailRepository;
        this.mfaUserRepository = mfaUserRepository;
        this.notifier = notifier;
        this.passwordEncoderService = passwordEncoderService;
    }

    /**
     * Creates a new user and locks the account until email verification.
     * Generates and hashes password + salt.
     */
    @Notification(mediaType = NotificationMediaType.EMAIL, type = "USER_SIGNUP", generateCode = true)
    public UserCredentials save(final UserCredentials userCredentials, @NotificationEmail final String emailAddress) {
        // Hash the raw password with Argon2id unless it is already an Argon2id hash
        // (guards against double-processing a previously saved credential).
        if (!passwordEncoderService.isEncoded(userCredentials.getPassword())) {
            // Auth-hardening: enforce the default-realm password policy on public self-service signup
            // (this path carries no realm, so the platform/master policy applies).
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.enforce(RealmConfig.ADMIN_REALM_ID, null,
                        userCredentials.getUsername(), userCredentials.getPassword());
            }
            final String password = passwordEncoderService.encode(userCredentials.getPassword());
            final String username = userCredentials.getUsername();

            userCredentials.setUsername(username.toLowerCase());
            userCredentials.setAccountLocked(true);
            userCredentials.setPassword(password);
            userCredentials.setPasswordSaltValue(null);
            // Self-registration belongs to the realm whose register page was used: its home realm, its realm link
            // and the realm's default role (it used to get no realm at all).
            final String realm = currentRealm();
            userCredentials.setRealmId(realm);
            final UserCredentials saved = userCredentialsRepository.save(userCredentials);
            if (tenantUsers != null) {
                final io.helixiam.authorization.domain.tenant.TenantUser link = new io.helixiam.authorization.domain.tenant.TenantUser();
                link.setTenantId(realm);
                link.setUserId(saved.getUserId());
                final io.helixiam.authorization.domain.tenant.TenantUser savedLink = tenantUsers.save(link);
                if (defaultRoles != null) {
                    defaultRoles.assignDefaultRole(realm, saved.getUserId(), savedLink.getTenantUserId());
                }
            }
            return saved;
        }

        return null;
    }

    /**
     * Starts a password reset. {@code typed} (username or email address) only finds the account in the realm; the
     * link goes to the account's stored email address, off the request thread ({@link PasswordResetMailer}). An unknown
     * account or one without an address gets nothing, and the caller cannot tell: both lookups always run, and the
     * answer does not depend on the account.
     *
     * @return the account found, or null (for the caller's own use; never to be shown to the requester)
     */
    public UserCredentials resetPasswordRequest(final String typed) {
        final String identifier = typed == null ? "" : typed.trim().toLowerCase();
        final String realm = currentRealm();
        // Both lookups always run, so an existing and an unknown account take the same work.
        final java.util.Optional<UserCredentials> byUsername = userCredentialsRepository.findByRealmIdAndUsername(realm,
                identifier);
        final java.util.Optional<UserCredentials> byEmail = userCredentialsRepository.findByRealmIdAndEmail(realm,
                identifier);
        final UserCredentials account = byUsername.or(() -> byEmail).orElse(null);
        if (account != null && passwordResetMailer != null) {
            passwordResetMailer.send(account);
        }
        return account;
    }

    /**
     * Sets a new password with an emailed reset code. The code must exist, be unexpired
     * ({@code helix.notification.reset-password.code-ttl}) and unused: it is consumed atomically, so it works once.
     *
     * @return false when the code is unknown, expired or already used (the reset page says so); true once the new
     *         password is stored
     */
    @org.springframework.transaction.annotation.Transactional
    public boolean resetPasswordUpdate(final ChangePassword changePassword) {
        final String code = changePassword.getCode();
        if (code == null || code.isBlank()) {
            return false;
        }
        final java.util.Optional<io.helixiam.notification.domain.NotificationCode> found =
                notificationCodeRepository.findByCodeAndType(io.helixiam.notification.NotificationCodePolicy.hash(code), "USER_RESET_PASSWORD");
        if (found.isEmpty()) {
            return false;
        }
        final io.helixiam.notification.domain.NotificationCode notificationCode = found.get();
        if (!codePolicy.isValid(notificationCode, java.time.Instant.now())) {
            notificationCodeRepository.consume(notificationCode.getCode(), "USER_RESET_PASSWORD"); // expired: gone
            return false;
        }
        final String userId = notificationCode.getIdentifier();
        // Auth-hardening: enforce the default-realm password policy on the public self-service reset (before the
        // code is used up, so a refused password leaves the link working).
        if (passwordPolicyEnforcer != null) {
            final String username = userCredentialsRepository.findByUserId(userId)
                    .map(UserCredentials::getUsername).orElse(null);
            passwordPolicyEnforcer.enforce(RealmConfig.ADMIN_REALM_ID, userId, username,
                    changePassword.getNewPassword());
        }
        if (notificationCodeRepository.consume(notificationCode.getCode(), "USER_RESET_PASSWORD") != 1) {
            return false; // used by a concurrent request
        }
        final String password = passwordEncoderService.encode(changePassword.getNewPassword());
        changePassword.setUserId(userId);
        changePassword.setNewPassword(password);
        changePassword.setPasswordSaltValue(null);
        changePasswordRepository.save(changePassword);
        if (passwordPolicyEnforcer != null) {
            passwordPolicyEnforcer.recordHistory(RealmConfig.ADMIN_REALM_ID, userId, password);
        }
        return true;
    }

    /** Whether {@code code} is a reset code that still works (unknown, used and expired codes do not). */
    public boolean resetCodeUsable(final String code) {
        return code != null && !code.isBlank() && notificationCodeRepository.findByCodeAndType(
                        io.helixiam.notification.NotificationCodePolicy.hash(code), "USER_RESET_PASSWORD")
                .filter(c -> codePolicy.isValid(c, java.time.Instant.now())).isPresent();
    }

    /**
     * Returns a map of claims (user attributes) for a given user.
     */
    public Map<String, String> userClaims(final String userId) {
        final UserCredentials userCredentials = userCredentialsRepository.findByUserId(userId).orElse(null);
        if (userCredentials == null) {
            return new HashMap<>();
        }

        // Start from the column-backed identity (username + optional email), then let any explicit
        // profile attribute override it. These map downstream to `preferred_username`/`email` claims.
        final Map<String, String> claims = new HashMap<>();
        if (userCredentials.getUsername() != null) {
            claims.put("username", userCredentials.getUsername());
        }
        if (userCredentials.getEmail() != null) {
            claims.put("email", userCredentials.getEmail());
        }
        if (userCredentials.getUserAttributes() != null) {
            claims.putAll(userCredentials.getUserAttributes());
        }
        return claims;
    }

    /**
     * Verifies email using signup code and sends internal registration notification.
     *
     * @return whether {@code code} was a pending verification code (item A7: the code page says when it is not)
     */
    @org.springframework.transaction.annotation.Transactional
    public boolean verifyEmail(final String code) {
        return verifyEmailFor(code) != null;
    }

    /**
     * Item A8: {@link #verifyEmail} that also says whose address it was.
     *
     * @return the verified user's username ({@code ""} when the account is gone), or null when {@code code} was not a
     *         pending verification code
     */
    @org.springframework.transaction.annotation.Transactional
    public String verifyEmailFor(final String code) {
        if (code == null || code.isBlank()) {
            return null;
        }
        final java.util.Optional<io.helixiam.notification.domain.NotificationCode> found =
                notificationCodeRepository.findByCodeAndType(io.helixiam.notification.NotificationCodePolicy.hash(code), "USER_SIGNUP");
        if (found.isPresent() && !codePolicy.isValid(found.get(), java.time.Instant.now())) {
            notificationCodeRepository.consume(found.get().getCode(), "USER_SIGNUP"); // expired: gone
            return null;
        }
        // Single use: only the request that consumes the code verifies.
        final java.util.Optional<io.helixiam.notification.domain.NotificationCode> pending = found
                .filter(c -> notificationCodeRepository.consume(c.getCode(), "USER_SIGNUP") == 1);
        pending.ifPresent(notificationCode -> {
            final VerifyEmail verifyEmail = new VerifyEmail();
            verifyEmail.setUserId(notificationCode.getIdentifier());

            verifyEmailRepository.save(verifyEmail);
            if (emailBounces != null) {
                emailBounces.clear(notificationCode.getIdentifier()); // verified again: a bounce no longer holds
            }

            try {
                if (registrationNotificationRecipient != null && !registrationNotificationRecipient.isBlank()) {
                    userCredentialsRepository.findByUserId(notificationCode.getIdentifier()).ifPresent(userCredentials -> {
                        final NotificationRequest notificationRequest = new NotificationRequest("NEW_REGISTERED_USER");
                        notificationRequest.setEmailAddress(registrationNotificationRecipient);
                        notificationRequest.getAdditionalData().putAll(userCredentials.getUserAttributes());

                        notifier.sendEmailNotification(notificationRequest);
                    });
                }
            } catch (final Exception e) {
                // swallow all in case something goes wrong
            }
        });

        return pending.map(c -> userCredentialsRepository.findByUserId(c.getIdentifier())
                .map(UserCredentials::getUsername).orElse("")).orElse(null);
    }

    /**
     * Enables MFA for a given user.
     */
    public void enableMfa(final String userId) {
        final MfaUser mfaUser = new MfaUser();
        mfaUser.setUserId(userId);
        mfaUserRepository.save(mfaUser);
    }

    /**
     * Returns all role names for the given user.
     */
    public Set<String> getUserInRoles(final String userId) {
        final UserCredentials userCredentials = userCredentialsRepository.findByUserId(userId).orElse(null);
        if (userCredentials != null) {
            final Set<String> roles = new HashSet<>();
            userCredentials.getUserRoles().forEach(role -> roles.add(role.getTenantRoleName()));
            return roles;
        }

        return Collections.emptySet();
    }

    private io.helixiam.authorization.repository.tenant.TenantUserRepository tenantUsers;
    private io.helixiam.authorization.service.role.DefaultRoleAssignmentService defaultRoles;

    @Autowired(required = false)
    public void setTenantUsers(final io.helixiam.authorization.repository.tenant.TenantUserRepository tenantUsers) {
        this.tenantUsers = tenantUsers;
    }

    @Autowired(required = false)
    public void setDefaultRoles(final io.helixiam.authorization.service.role.DefaultRoleAssignmentService defaultRoles) {
        this.defaultRoles = defaultRoles;
    }

    private static String currentRealm() {
        final String realm = io.helixiam.authorization.security.realm.RealmContextHolder.get();
        return realm == null ? RealmConfig.ADMIN_REALM_ID : realm;
    }
}
