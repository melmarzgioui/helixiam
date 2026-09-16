/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.LoginCredentials;
import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.tenant.TenantUser;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.tenant.TenantUserRepository;
import io.helixiam.authorization.service.security.LoginFailureService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service responsible for handling user authentication logic.
 *
 * Validates login credentials and matches them against stored user records. Passwords
 * are verified via {@link PasswordEncoderService} (Argon2id, with legacy SHA-256+salt
 * fallback); legacy credentials are transparently re-hashed to Argon2id on a successful
 * login.
 *
 * <p>Auth-hardening (feature 1): wraps the credential check with the per-realm account-lockout /
 * brute-force state machine ({@link LoginFailureService}). A locked-out user is returned with a transient
 * {@code accountLocked} flag so the publisher's Spring Security chain raises {@code LockedException} (a
 * generic "account temporarily locked" outcome that avoids user enumeration); a wrong password records a
 * failure; a correct password clears the counter.
 */
@Service
public class LoginService {

    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoderService passwordEncoderService;
    private final LoginFailureService loginFailureService;
    private final RealmService realmService;
    private final TenantUserRepository tenantUserRepository;

    @Autowired
    public LoginService(final UserCredentialsRepository userCredentialsRepository,
                        final PasswordEncoderService passwordEncoderService,
                        final LoginFailureService loginFailureService,
                        final RealmService realmService,
                        final TenantUserRepository tenantUserRepository) {
        this.userCredentialsRepository = userCredentialsRepository;
        this.passwordEncoderService = passwordEncoderService;
        this.loginFailureService = loginFailureService;
        this.realmService = realmService;
        this.tenantUserRepository = tenantUserRepository;
    }

    /**
     * Authenticates a user based on username and password.
     *
     * `@param loginCredentials` the submitted login credentials
     * `@return` the matching `UserCredentials` if authentication is successful; a locked user (transient
     * {@code accountLocked}) when brute-force-locked; `null` otherwise
     */
    public UserCredentials loginUser(final LoginCredentials loginCredentials) {
        if (StringUtils.isEmpty(loginCredentials.getUsername()) || StringUtils.isEmpty(loginCredentials.getPassword())) {
            return null;
        }

        // "login with email": the submitted identifier resolves an account by username
        // first, then falls back to email — so a user may sign in with either. Username wins on the rare
        // chance one account's email equals another's username.
        final UserCredentials userCredentials = userCredentialsRepository
                .findByUsername(loginCredentials.getUsername())
                .or(() -> userCredentialsRepository.findByEmail(loginCredentials.getUsername()))
                .orElse(null);

        if (userCredentials == null) {
            return null;
        }

        // Auth-hardening (feature 1): the realms this user belongs to that have lockout enabled.
        final List<RealmConfig> lockoutRealms = lockoutRealmsFor(userCredentials.getUserId());

        // If already locked out in any realm, short-circuit BEFORE the password check so we never reveal
        // whether the password was correct. Return the user with a transient lock flag → LockedException.
        for (final RealmConfig realm : lockoutRealms) {
            if (loginFailureService.isLockedOut(realm, userCredentials.getUserId())) {
                userCredentials.setAccountLocked(true);
                return userCredentials;
            }
        }

        if (!passwordEncoderService.matches(
                loginCredentials.getPassword(),
                userCredentials.getPassword(),
                userCredentials.getPasswordSaltValue())) {
            // Record the failure against each lockout-enabled realm; surface the lock immediately if hit.
            boolean nowLocked = false;
            for (final RealmConfig realm : lockoutRealms) {
                nowLocked |= loginFailureService.recordFailure(realm, userCredentials.getUserId());
            }
            if (nowLocked) {
                userCredentials.setAccountLocked(true);
                return userCredentials;
            }
            return null;
        }

        // Successful password — clear any accumulated failures.
        for (final RealmConfig realm : lockoutRealms) {
            loginFailureService.recordSuccess(realm, userCredentials.getUserId());
        }

        // Transparent migration: upgrade a legacy SHA-256+salt hash to Argon2id once the
        // user has proven the password, then drop the now-unused salt.
        if (passwordEncoderService.upgradeNeeded(userCredentials.getPassword())) {
            userCredentials.setPassword(passwordEncoderService.encode(loginCredentials.getPassword()));
            userCredentials.setPasswordSaltValue(null);
            userCredentialsRepository.save(userCredentials);
        }

        return userCredentials;
    }

    /** The realm configs the user is bound to that have account-lockout enabled. */
    private List<RealmConfig> lockoutRealmsFor(final String userId) {
        return tenantUserRepository.findAllByUserId(userId).stream()
                .map(TenantUser::getTenantId)
                .distinct()
                .map(realmService::getOrDefault)
                .filter(RealmConfig::isLockoutEnabled)
                .toList();
    }
}
