/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import io.helixiam.authorization.domain.realm.RealmConfig;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.realm.RealmConfigRepository;
import io.helixiam.authorization.service.PasswordEncoderService;
import io.helixiam.authorization.service.mfa.TotpService;
import io.helixiam.authorization.service.security.LoginFailureService;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * B1: checks a password or an authenticator code typed into the account console (re-authentication, confirming new
 * recovery codes). A wrong one counts toward the realm's account lockout exactly like a wrong sign-in; a locked-out
 * account is refused even with the right one.
 */
@Service
public class AccountCredentialCheck {

    /** The outcome of a check. */
    public enum Result { OK, WRONG, LOCKED }

    private final UserCredentialsRepository users;
    private final PasswordEncoderService passwords;
    private final TotpService totp;
    private final RealmConfigRepository realms;
    private final LoginFailureService failures;

    public AccountCredentialCheck(final UserCredentialsRepository users, final PasswordEncoderService passwords,
                                  final TotpService totp, final RealmConfigRepository realms,
                                  final LoginFailureService failures) {
        this.users = users;
        this.passwords = passwords;
        this.totp = totp;
        this.realms = realms;
        this.failures = failures;
    }

    public Result password(final String realmId, final String userId, final String rawPassword) {
        final Optional<RealmConfig> realm = realms.findById(realmId);
        if (realm.isPresent() && failures.isLockedOut(realm.get(), userId)) {
            return Result.LOCKED;
        }
        final UserCredentials user = users.findByUserId(userId).orElse(null);
        if (user != null && rawPassword != null && !rawPassword.isEmpty() && user.getPassword() != null
                && passwords.matches(rawPassword, user.getPassword(), user.getPasswordSaltValue())) {
            return Result.OK;
        }
        return failed(realm, userId);
    }

    /** A current code of the user's authenticator app (each code is accepted once). */
    public Result totp(final String realmId, final String userId, final String code) {
        final Optional<RealmConfig> realm = realms.findById(realmId);
        if (realm.isPresent() && failures.isLockedOut(realm.get(), userId)) {
            return Result.LOCKED;
        }
        return totp.verify(userId, code) ? Result.OK : failed(realm, userId);
    }

    private Result failed(final Optional<RealmConfig> realm, final String userId) {
        return realm.isPresent() && failures.recordFailure(realm.get(), userId) ? Result.LOCKED : Result.WRONG;
    }
}
