/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.adminrbac;

import io.helixiam.authorization.security.SignInAuthorities;
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

    /** Prefix of every realm-admin authority; see {@link #isReservedRoleName}. */
    public static final String RESERVED_ROLE_PREFIX = DefaultRoles.ADMIN + "_";

    /** What a request for a reserved role name is told. */
    public static final String RESERVED_ROLE_MESSAGE = "Role names starting with 'admin_' or 'FACTOR_' are reserved.";

    /**
     * True for a role name that must never be created (any case):
     * <ul>
     *   <li>{@code admin_…}: a realm id may contain {@code _}, so a role {@code admin_prod} in realm {@code acme} would
     *       carry the authority {@code admin_prod_acme}, indistinguishable from "admin of realm {@code prod_acme}", and
     *       would also pass {@link #isAdminOfAny}. Reserving the prefix keeps {@code admin_<realmId>} unambiguous.</li>
     *   <li>{@code FACTOR_…}: Spring Security 7's sign-in factor authorities ({@code FACTOR_PASSWORD} on every password
     *       login, see {@link SignInAuthorities}); a role of that name would be granted by the factor.</li>
     * </ul>
     */
    public static boolean isReservedRoleName(final String roleName) {
        return roleName != null && (roleName.regionMatches(true, 0, RESERVED_ROLE_PREFIX, 0, RESERVED_ROLE_PREFIX.length())
                || SignInAuthorities.isFactorName(roleName));
    }

    private static String realmAdminAuthority(final String realmId) {
        return DefaultRoles.ADMIN + "_" + realmId;
    }

    /** True when the principal holds {@code admin_<realmId>} for that realm, or is a master-realm admin. */
    public static boolean isAdminOf(final Authentication auth, final String realmId) {
        if (auth == null || realmId == null || realmId.isBlank()) {
            return false;
        }
        final String needed = realmAdminAuthority(realmId);
        // The master realm is the administrative realm (Keycloak model): its admins administer every realm —
        // that is how a new realm is provisioned at all. Admins of any other realm stay confined to it.
        final String master = realmAdminAuthority(io.helixiam.authorization.domain.realm.RealmConfig.ADMIN_REALM_ID);
        return SignInAuthorities.roleNames(auth).stream().anyMatch(a -> needed.equals(a) || master.equals(a));
    }

    /** True when the principal is an admin of the master (administrative) realm. */
    public static boolean isMasterAdmin(final Authentication auth) {
        if (auth == null) {
            return false;
        }
        final String master = realmAdminAuthority(io.helixiam.authorization.domain.realm.RealmConfig.ADMIN_REALM_ID);
        return SignInAuthorities.roleNames(auth).stream().anyMatch(master::equals);
    }

    /** True when the principal is an admin of ANY realm (for realm-independent admin routes). */
    public static boolean isAdminOfAny(final Authentication auth) {
        if (auth == null) {
            return false;
        }
        return SignInAuthorities.roleNames(auth).stream().anyMatch(a -> a.startsWith(DefaultRoles.ADMIN + "_"));
    }
}
