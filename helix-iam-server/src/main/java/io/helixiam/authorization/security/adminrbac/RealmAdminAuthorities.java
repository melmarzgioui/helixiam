/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.service.role.DefaultRoles;
import org.springframework.security.core.Authentication;

/**
 * Canonical "is this principal an admin of realm X" check for the multi-tenant admin surface.
 *
 * <p>Principal authorities are {@code <roleName>_<realmId>} (see {@code UserRoles.getTenantRoleName()} /
 * {@code UserCredentials.getAuthorities()}), so realm admin is exactly {@code admin_<realmId>}. This is
 * centralised so the request-level {@link AdminAuthorizationManager} (which resolves the realm from the
 * PATH) and controllers that resolve a realm from a QUERY PARAMETER apply the same rule and cannot drift —
 * the drift was the pentest's cross-tenant leak (a realm admin reading another realm's figures via
 * {@code ?realm=}).
 */
public final class RealmAdminAuthorities {

    private RealmAdminAuthorities() {
    }

    private static String realmAdminAuthority(final String realmId) {
        return DefaultRoles.ADMIN + "_" + realmId;
    }

    /** True when the principal holds {@code admin_<realmId>} for exactly that realm. */
    public static boolean isAdminOf(final Authentication auth, final String realmId) {
        if (auth == null || realmId == null || realmId.isBlank()) {
            return false;
        }
        final String needed = realmAdminAuthority(realmId);
        return auth.getAuthorities().stream()
                .map(a -> a == null ? null : a.getAuthority())
                .anyMatch(needed::equals);
    }

    /** True when the principal is an admin of ANY realm (for realm-independent admin routes). */
    public static boolean isAdminOfAny(final Authentication auth) {
        if (auth == null) {
            return false;
        }
        return auth.getAuthorities().stream()
                .map(a -> a == null ? null : a.getAuthority())
                .anyMatch(a -> a != null && a.startsWith(DefaultRoles.ADMIN + "_"));
    }
}
