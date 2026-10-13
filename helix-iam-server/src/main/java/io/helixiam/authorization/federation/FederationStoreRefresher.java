/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Helix IAM E8.3: loads admin-managed identity-provider configs from the store and registers them in
 * the live {@link IdentityProviderRegistry} — so a connection created in the console (E8.2) becomes
 * loginable on the next refresh, without a restart. Disabled connections are skipped; a malformed one
 * is logged and skipped without sinking the rest of the refresh.
 *
 * <p>Final review F1: {@link #refreshAll()} (startup) loads every realm; {@link #refresh(String)} (after an admin
 * write) replaces only that realm's providers. Production readiness item 1: {@link #refreshChanged()} (polled) reloads
 * the realms another replica wrote, and every publication is version-ordered.
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
     * Reloads the registry's store-backed providers of one realm, leaving every other realm's. Returns the number
     * published (0 when a newer version of the realm was published meanwhile).
     *
     * <p>Production readiness item 1: the realm's store version is read BEFORE its configs, so the configs are at least
     * that new, and the set is published only if no newer version is (version-ordered publication): two concurrent
     * refreshes, which build outside the registry lock, can never publish the older set over the newer one.
     */
    public int refresh(final String realmId) {
        return refresh(realmId, source.version(realmId));
    }

    private int refresh(final String realmId, final long version) {
        final List<IdentityProvider> providers = build(source.load(realmId));
        return registry.reload(realmId, providers, version) ? providers.size() : 0;
    }

    /** Loads the store-backed providers of every realm (startup), replacing whatever was loaded. Returns the number. */
    public int refreshAll() {
        final Map<String, Long> versions = source.versions(); // before the configs, as in refresh(realm)
        final Map<String, List<IdentityProviderConfig>> byRealm = new LinkedHashMap<>();
        for (final IdentityProviderConfig config : source.loadAll()) {
            byRealm.computeIfAbsent(config.realmId(), r -> new ArrayList<>()).add(config);
        }
        final Map<String, List<IdentityProvider>> providers = new LinkedHashMap<>();
        byRealm.forEach((realmId, configs) -> providers.put(realmId, build(configs)));
        registry.replaceAll(providers, versions);
        return providers.values().stream().mapToInt(List::size).sum();
    }

    /**
     * The cross-replica poll (production readiness item 1, {@link FederationStoreVersionPoller}): reloads every realm
     * whose store version moved past the published one (a write or a realm import on another replica, or on this one
     * when its own refresh failed). One cheap query when nothing changed. Returns the number of realms reloaded.
     */
    public int refreshChanged() {
        int reloaded = 0;
        for (final Map.Entry<String, Long> entry : source.versions().entrySet()) {
            if (entry.getValue() > registry.version(entry.getKey())) {
                refresh(entry.getKey(), entry.getValue());
                reloaded++;
            }
        }
        return reloaded;
    }

    private List<IdentityProvider> build(final List<IdentityProviderConfig> configs) {
        return configs.stream()
                .filter(IdentityProviderConfig::enabled)
                .map(this::buildQuietly)
                .filter(Objects::nonNull)
                .toList();
    }

    private IdentityProvider buildQuietly(final IdentityProviderConfig config) {
        try {
            return factory.fromStored(config);
        } catch (final RuntimeException e) {
            LOG.warn("Skipping malformed identity-provider config '{}' in realm '{}': {}",
                    LogSafe.sanitize(config.alias()), LogSafe.sanitize(config.realmId()),
                    LogSafe.sanitize(e.getMessage()));
            return null;
        }
    }
}
