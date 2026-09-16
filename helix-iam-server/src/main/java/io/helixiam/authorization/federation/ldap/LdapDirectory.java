/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.ldap;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Helix IAM E5.2: the directory-bind seam for the LDAP broker. Implementations search for the user
 * and bind with the supplied password; on success they return the user's directory attributes,
 * otherwise empty. Behind a seam so {@link LdapAuthenticationService}'s attribute→identity mapping is
 * unit-testable without a real directory; the live impl uses JDK JNDI ({@link JndiLdapDirectory}).
 */
public interface LdapDirectory {

    /** @return the user's attributes if the bind succeeds; empty if the user is unknown or the password is wrong. */
    Optional<Map<String, String>> authenticate(LdapProviderConfig config, String username, String password);

    /**
     * Helix IAM B10: list every user under the directory's search base (service-account bind only, no
     * per-user password) — the source rows for an LDAP sync. Default returns empty so an implementation
     * that cannot enumerate degrades to "nothing to sync" rather than failing.
     */
    default List<Map<String, String>> listUsers(final LdapProviderConfig config) {
        return List.of();
    }
}
