/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.security;

import io.helixiam.authorization.domain.realm.RealmConfig;

import java.util.ArrayList;
import java.util.List;

/**
 * Auth-hardening (feature 3): a pure, unit-testable password-policy validator. Builds the rule set from a
 * {@link RealmConfig} and checks a raw password against it. Carries no I/O so it can be exercised in
 * isolation; history is checked separately by the caller (it needs the encoder + stored hashes).
 *
 * <p>{@link #validate} returns the list of human-readable violations; an empty list means the password is
 * acceptable. The caller turns a non-empty result into a rejection.
 */
public final class PasswordPolicy {

    private final int minLength;
    private final boolean requireUppercase;
    private final boolean requireLowercase;
    private final boolean requireDigit;
    private final boolean requireSpecial;
    private final boolean notUsername;

    public PasswordPolicy(final int minLength, final boolean requireUppercase, final boolean requireLowercase,
                          final boolean requireDigit, final boolean requireSpecial, final boolean notUsername) {
        this.minLength = minLength;
        this.requireUppercase = requireUppercase;
        this.requireLowercase = requireLowercase;
        this.requireDigit = requireDigit;
        this.requireSpecial = requireSpecial;
        this.notUsername = notUsername;
    }

    /** Builds the policy from a realm's persisted configuration. */
    public static PasswordPolicy fromRealm(final RealmConfig config) {
        return new PasswordPolicy(config.getPasswordMinLength(), config.isPasswordRequireUppercase(),
                config.isPasswordRequireLowercase(), config.isPasswordRequireDigit(),
                config.isPasswordRequireSpecial(), config.isPasswordNotUsername());
    }

    /**
     * @param rawPassword the candidate password
     * @param username    the account's username (for the {@code notUsername} rule); may be {@code null}
     * @return the violations, empty when the password satisfies every rule
     */
    public List<String> validate(final String rawPassword, final String username) {
        final List<String> violations = new ArrayList<>();
        final String pw = rawPassword == null ? "" : rawPassword;
        if (pw.length() < minLength) {
            violations.add("Password must be at least " + minLength + " characters.");
        }
        if (requireUppercase && pw.chars().noneMatch(Character::isUpperCase)) {
            violations.add("Password must contain an uppercase letter.");
        }
        if (requireLowercase && pw.chars().noneMatch(Character::isLowerCase)) {
            violations.add("Password must contain a lowercase letter.");
        }
        if (requireDigit && pw.chars().noneMatch(Character::isDigit)) {
            violations.add("Password must contain a digit.");
        }
        if (requireSpecial && pw.chars().noneMatch(PasswordPolicy::isSpecial)) {
            violations.add("Password must contain a special character.");
        }
        if (notUsername && username != null && !username.isBlank()
                && pw.equalsIgnoreCase(username.trim())) {
            violations.add("Password must not equal the username.");
        }
        return violations;
    }

    /** True when the password satisfies every rule. */
    public boolean isValid(final String rawPassword, final String username) {
        return validate(rawPassword, username).isEmpty();
    }

    private static boolean isSpecial(final int c) {
        return !Character.isLetterOrDigit(c) && !Character.isWhitespace(c);
    }
}
