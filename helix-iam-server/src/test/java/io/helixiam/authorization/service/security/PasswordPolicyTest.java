/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.security;

import io.helixiam.authorization.domain.realm.RealmConfig;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Auth-hardening (feature 3): the pure password-policy validator. */
class PasswordPolicyTest {

    @Test
    void minLength_isEnforced() {
        final PasswordPolicy policy = new PasswordPolicy(12, false, false, false, false, false);
        assertThat(policy.isValid("short", "alice")).isFalse();
        assertThat(policy.isValid("longenoughpassword", "alice")).isTrue();
    }

    @Test
    void characterClasses_areEnforcedIndependently() {
        final PasswordPolicy policy = new PasswordPolicy(8, true, true, true, true, false);
        assertThat(policy.validate("lowercaseonly", null)).isNotEmpty();      // no upper/digit/special
        assertThat(policy.isValid("Abcdef1!", null)).isTrue();
        assertThat(policy.isValid("ABCDEF1!", null)).isFalse();               // missing lowercase
        assertThat(policy.isValid("Abcdefgh", null)).isFalse();               // missing digit + special
    }

    @Test
    void notUsername_rejectsCaseInsensitiveMatch() {
        final PasswordPolicy policy = new PasswordPolicy(4, false, false, false, false, true);
        assertThat(policy.isValid("Alice", "alice")).isFalse();
        assertThat(policy.isValid("Alice", "  alice ")).isFalse();
        assertThat(policy.isValid("different", "alice")).isTrue();
    }

    @Test
    void emptyPolicy_acceptsAnythingMeetingLength() {
        final PasswordPolicy policy = new PasswordPolicy(1, false, false, false, false, false);
        assertThat(policy.validate("x", "user")).isEmpty();
    }

    @Test
    void fromRealm_mapsEveryFlag() {
        final RealmConfig realm = RealmConfig.defaults("gov");
        realm.setPasswordMinLength(10);
        realm.setPasswordRequireUppercase(true);
        realm.setPasswordRequireSpecial(true);
        realm.setPasswordNotUsername(true);

        final PasswordPolicy policy = PasswordPolicy.fromRealm(realm);
        assertThat(policy.isValid("nouppercaseorspecial", "bob")).isFalse();
        assertThat(policy.isValid("ValidPass1!", "bob")).isTrue();
    }

    @Test
    void nullPassword_isTreatedAsEmpty_andFailsLength() {
        final PasswordPolicy policy = new PasswordPolicy(8, false, false, false, false, false);
        assertThat(policy.isValid(null, "u")).isFalse();
    }
}
