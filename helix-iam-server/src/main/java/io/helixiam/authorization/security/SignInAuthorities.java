/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Roles versus sign-in factors in a principal's authorities.
 *
 * <p>Spring Security 7 adds a {@link FactorGrantedAuthority} to an authentication to record HOW the user signed in:
 * {@code FACTOR_PASSWORD} for every password login ({@code AbstractUserDetailsAuthenticationProvider}). HelixIAM's
 * authorities are otherwise its realm roles ({@code <role>_<realm>}), and admin RBAC matches them by name, so a factor
 * must never be read as a role: a realm role named {@code FACTOR_PASSWORD} would otherwise be granted to every password
 * login. Every place that derives roles from authorities goes through {@link #roleNames}, the {@code FACTOR_} prefix is
 * reserved for role names (any case), and token role claims drop it.
 *
 * <p>Every sign-in path carries exactly one factor, so the authorities differ only in that factor and the derived roles
 * are identical: password ({@code FACTOR_PASSWORD}, added by Spring Security), magic link ({@link #MAGIC_LINK}),
 * federated login ({@link #FEDERATED}) and impersonation ({@link #IMPERSONATION}).
 */
public final class SignInAuthorities {

    /** Prefix of every factor authority; reserved for role names. */
    public static final String FACTOR_PREFIX = "FACTOR_";
    /** A sign-in by a one-time link sent by email. */
    public static final String MAGIC_LINK = FactorGrantedAuthority.OTT_AUTHORITY;
    /** A sign-in at an external identity provider (OIDC, SAML, eID, EUDI Wallet). */
    public static final String FEDERATED = FACTOR_PREFIX + "FEDERATED";
    /** A session an administrator opened as the user. */
    public static final String IMPERSONATION = FACTOR_PREFIX + "IMPERSONATION";

    private SignInAuthorities() {
    }

    /** True for a name in the factor namespace ({@code FACTOR_…}, any case): never a role. */
    public static boolean isFactorName(final String name) {
        return name != null && name.regionMatches(true, 0, FACTOR_PREFIX, 0, FACTOR_PREFIX.length());
    }

    /** True for a factor authority, by type or by its reserved name. */
    public static boolean isFactor(final GrantedAuthority authority) {
        return authority instanceof FactorGrantedAuthority || (authority != null && isFactorName(authority.getAuthority()));
    }

    /** The principal's role authorities (non-blank, never a factor), in order and without duplicates. */
    public static List<String> roleNames(final Authentication authentication) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return List.of();
        }
        return authentication.getAuthorities().stream()
                .filter(Objects::nonNull)
                .filter(a -> !isFactor(a))
                .map(GrantedAuthority::getAuthority)
                .filter(s -> s != null && !s.isBlank())
                .distinct()
                .toList();
    }

    /** The factor authorities of the principal, by name. */
    public static List<String> factorsOf(final Authentication authentication) {
        if (authentication == null || authentication.getAuthorities() == null) {
            return List.of();
        }
        return authentication.getAuthorities().stream()
                .filter(a -> a instanceof FactorGrantedAuthority)
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

    /**
     * An authenticated token for a sign-in that did not go through the password provider: the user's roles (without
     * any factor-named authority) plus exactly one factor, as the password provider produces for a password login.
     */
    public static UsernamePasswordAuthenticationToken authenticated(final UserDetails user, final String factorAuthority) {
        final Collection<? extends GrantedAuthority> userAuthorities = user.getAuthorities();
        final List<GrantedAuthority> authorities = new ArrayList<>();
        if (userAuthorities != null) {
            userAuthorities.stream().filter(Objects::nonNull).filter(a -> !isFactor(a)).forEach(authorities::add);
        }
        authorities.add(FactorGrantedAuthority.fromAuthority(factorAuthority));
        return UsernamePasswordAuthenticationToken.authenticated(user, null, authorities);
    }
}
