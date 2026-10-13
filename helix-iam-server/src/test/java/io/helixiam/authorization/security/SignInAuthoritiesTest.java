/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import io.helixiam.authorization.security.mfa.domain.MfaAuthentication;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring Security 7 adds a {@link FactorGrantedAuthority} ({@code FACTOR_PASSWORD}) to every password login. A factor
 * says how the user signed in; it is never a role, and every sign-in path carries exactly one.
 */
class SignInAuthoritiesTest {

    @Test
    void roleNames_dropEveryFactor_byTypeAndByName() {
        final List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("auditor_gov"));
        authorities.add(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY));
        authorities.add(new SimpleGrantedAuthority("FACTOR_PASSWORD")); // a plain authority with the reserved name
        authorities.add(new SimpleGrantedAuthority("factor_ott"));
        authorities.add(() -> " "); // a blank authority (SimpleGrantedAuthority refuses one)
        final Authentication auth = UsernamePasswordAuthenticationToken.authenticated("ada", null, authorities);

        assertThat(SignInAuthorities.roleNames(auth)).containsExactly("auditor_gov");
        assertThat(SignInAuthorities.roleNames(new MfaAuthentication(auth))).isEmpty(); // no authorities of its own
        assertThat(SignInAuthorities.roleNames(null)).isEmpty();
    }

    @Test
    void reservedNames_areTheFactorNamespace_inAnyCase() {
        assertThat(SignInAuthorities.isFactorName("FACTOR_PASSWORD")).isTrue();
        assertThat(SignInAuthorities.isFactorName("Factor_anything")).isTrue();
        assertThat(SignInAuthorities.isFactorName("FACTORY")).isFalse();
        assertThat(SignInAuthorities.isFactorName("auditor")).isFalse();
        assertThat(SignInAuthorities.isFactorName(null)).isFalse();
    }

    @Test
    void authenticated_carriesTheUsersRoles_plusExactlyOneFactor() {
        final UserDetails user = User.withUsername("ada").password("").authorities("auditor_gov", "FACTOR_PASSWORD").build();

        final UsernamePasswordAuthenticationToken magic = SignInAuthorities.authenticated(user, SignInAuthorities.MAGIC_LINK);

        assertThat(magic.isAuthenticated()).isTrue();
        assertThat(magic.getPrincipal()).isSameAs(user);
        assertThat(SignInAuthorities.roleNames(magic)).containsExactly("auditor_gov");
        assertThat(SignInAuthorities.factorsOf(magic)).containsExactly(FactorGrantedAuthority.OTT_AUTHORITY);
        assertThat(magic.getAuthorities()).filteredOn(a -> a instanceof FactorGrantedAuthority).hasSize(1);
    }

    @Test
    void everySignInPath_yieldsTheSameRoles() {
        final UserDetails user = User.withUsername("ada").password("").authorities("auditor_gov", "user_gov").build();
        // What Spring Security's AbstractUserDetailsAuthenticationProvider builds for a password login.
        final List<GrantedAuthority> passwordAuthorities = new ArrayList<>(user.getAuthorities());
        passwordAuthorities.add(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY));
        final Authentication password = UsernamePasswordAuthenticationToken.authenticated(user, null, passwordAuthorities);

        for (final String factor : List.of(SignInAuthorities.MAGIC_LINK, SignInAuthorities.FEDERATED,
                SignInAuthorities.IMPERSONATION)) {
            assertThat(SignInAuthorities.roleNames(SignInAuthorities.authenticated(user, factor)))
                    .containsExactlyInAnyOrderElementsOf(SignInAuthorities.roleNames(password));
        }
    }
}
