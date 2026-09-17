/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the canonical tenant-admin authority check — the shared rule that closes the pentest's cross-tenant
 * leak (a realm admin must not be treated as admin of a realm they do not administer).
 */
class RealmAdminAuthoritiesTest {

    private static Authentication principal(final String... authorities) {
        return new UsernamePasswordAuthenticationToken("u-1", "x", AuthorityUtils.createAuthorityList(authorities));
    }

    @Test
    void isAdminOf_requiresTheExactRealmAuthority() {
        final Authentication govAdmin = principal("admin_gov", "user_gov");
        assertThat(RealmAdminAuthorities.isAdminOf(govAdmin, "gov")).isTrue();
        // Cross-tenant: admin of gov is NOT admin of another realm.
        assertThat(RealmAdminAuthorities.isAdminOf(govAdmin, "fin")).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOf(govAdmin, "master")).isFalse();
    }

    @Test
    void isAdminOf_rejectsNonAdminAndLegacyAndBlankInputs() {
        assertThat(RealmAdminAuthorities.isAdminOf(principal("user_gov", "auditor_gov"), "gov")).isFalse();
        // Legacy ROLE_ADMIN_<realm> is deliberately not honoured.
        assertThat(RealmAdminAuthorities.isAdminOf(principal("ROLE_ADMIN_gov"), "gov")).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOf(null, "gov")).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOf(principal("admin_gov"), "")).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOf(principal("admin_gov"), null)).isFalse();
    }

    @Test
    void isAdminOfAny_trueOnlyForSomeAdminAuthority() {
        assertThat(RealmAdminAuthorities.isAdminOfAny(principal("admin_fin"))).isTrue();
        assertThat(RealmAdminAuthorities.isAdminOfAny(principal("user_gov", "auditor_fin"))).isFalse();
        assertThat(RealmAdminAuthorities.isAdminOfAny(null)).isFalse();
    }
}
