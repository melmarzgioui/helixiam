/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

/**
 * Helix IAM E8.3: loads admin-managed identity-provider configs from the store and registers them in
 * the live {@link IdentityProviderRegistry} — so a connection created in the console (E8.2) becomes
 * loginable on the next refresh, without a restart. Disabled connections are skipped; a malformed one
 * is logged and skipped without sinking the rest of the refresh.
 */
public class FederationStoreRefresher {

    private static final Logger LOG = LogManager.getLogger(FederationStoreRefresher.class);

    private final IdentityProviderConfigSource source;
    private final FederationProviderFactory factory;
    private final IdentityProviderRegistry registry;

    public FederationStoreRefresher(final IdentityProviderConfigSource source,
                                    final FederationProviderFactory factory,
                                    final IdentityProviderRegistry registry) {
        this.source = source;
        this.factory = factory;
        this.registry = registry;
    }

    /**
     * Reloads the registry's store-backed providers for a realm. Returns the number registered.
     */
    public int refresh(final String realmId) {
        final List<IdentityProvider> providers = source.load(realmId).stream()
                .filter(IdentityProviderConfig::enabled)
                .map(this::buildQuietly)
                .filter(java.util.Objects::nonNull)
                .toList();
        registry.reload(providers);
        return providers.size();
    }

    private IdentityProvider buildQuietly(final IdentityProviderConfig config) {
        try {
            return factory.fromStored(config);
        } catch (final RuntimeException e) {
            LOG.warn("Skipping malformed identity-provider config '{}' in realm '{}': {}",
                    config.alias(), config.realmId(), e.getMessage());
            return null;
        }
    }
}
