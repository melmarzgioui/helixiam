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
    private final PasswordEncoderService passwordEncoderService;

    // Auth-hardening (features 3+4): enforce the realm's password policy on the public self-service paths.
    // Field-injected + optional so the constructor (and existing UserService tests) are untouched, and the
    // public reset/signup paths (which carry no realm) fall back to the default-realm policy.
    @Autowired(required = false)
    private PasswordPolicyEnforcer passwordPolicyEnforcer;

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

            return userCredentialsRepository.save(userCredentials);
        }

        return null;
    }

    /**
     * Initiates password reset flow and sends email with reset code.
     */
    @Notification(mediaType = NotificationMediaType.EMAIL, type = "USER_RESET_PASSWORD", generateCode = true)
    public UserCredentials resetPasswordRequest(@NotificationEmail final String username) {
        return userCredentialsRepository.findByUsername(username).orElse(null);
    }

    /**
     * Updates password using reset code and new hashed password.
     */
    public boolean resetPasswordUpdate(final ChangePassword changePassword) {
        notificationCodeRepository.findByCodeAndType(changePassword.getCode(), "USER_RESET_PASSWORD").ifPresent(notificationCode -> {
            final String userId = notificationCode.getIdentifier();
            // Auth-hardening: enforce the default-realm password policy on the public self-service reset.
            if (passwordPolicyEnforcer != null) {
                final String username = userCredentialsRepository.findByUserId(userId)
                        .map(UserCredentials::getUsername).orElse(null);
                passwordPolicyEnforcer.enforce(RealmConfig.ADMIN_REALM_ID, userId, username,
                        changePassword.getNewPassword());
            }
            final String password = passwordEncoderService.encode(changePassword.getNewPassword());

            changePassword.setUserId(userId);
            changePassword.setNewPassword(password);
            changePassword.setPasswordSaltValue(null);

            changePasswordRepository.save(changePassword);
            if (passwordPolicyEnforcer != null) {
                passwordPolicyEnforcer.recordHistory(RealmConfig.ADMIN_REALM_ID, userId, password);
            }
            notificationCodeRepository.delete(notificationCode);
        });

        return true;
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
     */
    public boolean verifyEmail(final String code) {
        notificationCodeRepository.findByCodeAndType(code, "USER_SIGNUP").ifPresent(notificationCode -> {
            final VerifyEmail verifyEmail = new VerifyEmail();
            verifyEmail.setUserId(notificationCode.getIdentifier());

            verifyEmailRepository.save(verifyEmail);

            try {
                userCredentialsRepository.findByUserId(notificationCode.getIdentifier()).ifPresent(userCredentials -> {
                    final NotificationRequest notificationRequest = new NotificationRequest("NEW_REGISTERED_USER");
                    notificationRequest.setEmailAddress("contact@kubedna.com");
                    notificationRequest.getAdditionalData().putAll(userCredentials.getUserAttributes());

                    notifier.sendEmailNotification(notificationRequest);
                });
            } catch (final Exception e) {
                // swallow all in case something goes wrong
            }

            notificationCodeRepository.delete(notificationCode);
        });

        return true;
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
}
