/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;

import java.util.List;
import java.util.Map;

/**
 * Helix IAM E8.3: the seam the federation registry reads stored identity-provider configs from. In
 * production this is backed by the identity-provider config store (in process since RabbitMQ was removed); in tests
 * it's a simple stub. Keeping it an interface lets the registry refresh from the DB without coupling to the store.
 */
@FunctionalInterface
public interface IdentityProviderConfigSource {

    /** The persisted identity-provider configs for a realm. */
    List<IdentityProviderConfig> load(String realmId);

    /**
     * The persisted identity-provider configs of every realm (the startup load). A source that cannot list across
     * realms refuses, and the startup load then loads nothing.
     */
    default List<IdentityProviderConfig> loadAll() {
        throw new UnsupportedOperationException("This identity-provider config source cannot list every realm");
    }

    /**
     * Every realm's identity-provider config version, bumped in the transaction of each write (production readiness
     * item 1). The registry polls it to reload the realms another replica wrote, and labels what it publishes with it
     * so an older set never replaces a newer one. A source without versions answers none (every realm at version 0).
     */
    default Map<String, Long> versions() {
        return Map.of();
    }

    /** {@code realmId}'s identity-provider config version (0 when it was never written). */
    default long version(final String realmId) {
        return versions().getOrDefault(realmId, 0L);
    }
}
