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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Helix IAM E8.3: loads admin-managed identity-provider configs from the store and registers them in
 * the live {@link IdentityProviderRegistry} — so a connection created in the console (E8.2) becomes
 * loginable on the next refresh, without a restart. Disabled connections are skipped; a malformed one
 * is logged and skipped without sinking the rest of the refresh.
 *
 * <p>Final review F1: {@link #refreshAll()} (startup) loads every realm; {@link #refresh(String)} (after an admin
 * write) replaces only that realm's providers.
 *
 * <p>{@link #refreshChanged()} keeps every replica in step with the store: run periodically, it reloads each realm whose
 * stored connections differ from what this replica last loaded (a connection disabled, deleted, re-keyed or imported
 * through another replica, or by a realm import), and no other realm. So disabling a compromised identity provider takes
 * effect on every replica within one poll, not at their next restart.
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

    /** What this replica last loaded, per realm: alias → stored config (secrets included, never logged). */
    private final Map<String, Map<String, IdentityProviderConfig>> loaded = new HashMap<>();

    /** Reloads the registry's store-backed providers of one realm, leaving every other realm's. Returns the number. */
    public synchronized int refresh(final String realmId) {
        final List<IdentityProviderConfig> configs = source.load(realmId);
        final List<IdentityProvider> providers = build(configs);
        registry.reload(realmId, providers);
        remember(realmId, configs);
        return providers.size();
    }

    /** Loads the store-backed providers of every realm (startup), replacing whatever was loaded. Returns the number. */
    public synchronized int refreshAll() {
        final Map<String, List<IdentityProviderConfig>> byRealm = byRealm(source.loadAll());
        final Map<String, List<IdentityProvider>> providers = new LinkedHashMap<>();
        byRealm.forEach((realmId, configs) -> providers.put(realmId, build(configs)));
        registry.replaceAll(providers);
        loaded.clear();
        byRealm.forEach(this::remember);
        return providers.values().stream().mapToInt(List::size).sum();
    }

    /**
     * Reloads every realm whose stored connections changed since this replica last loaded them (including a realm whose
     * connections are all gone, or a realm that has its first); other realms are not touched. Returns the number of
     * realms reloaded.
     */
    public synchronized int refreshChanged() {
        final Map<String, List<IdentityProviderConfig>> byRealm = byRealm(source.loadAll());
        final Set<String> realms = new HashSet<>(loaded.keySet());
        realms.addAll(byRealm.keySet());
        int reloaded = 0;
        for (final String realmId : realms) {
            final List<IdentityProviderConfig> configs = byRealm.getOrDefault(realmId, List.of());
            if (byAlias(configs).equals(loaded.getOrDefault(realmId, Map.of()))) {
                continue;
            }
            registry.reload(realmId, build(configs));
            remember(realmId, configs);
            reloaded++;
            LOG.info("Identity providers of realm '{}' changed in the store; reloaded", LogSafe.sanitize(realmId));
        }
        return reloaded;
    }

    private static Map<String, List<IdentityProviderConfig>> byRealm(final List<IdentityProviderConfig> configs) {
        final Map<String, List<IdentityProviderConfig>> byRealm = new LinkedHashMap<>();
        for (final IdentityProviderConfig config : configs) {
            byRealm.computeIfAbsent(config.realmId(), r -> new ArrayList<>()).add(config);
        }
        return byRealm;
    }

    private static Map<String, IdentityProviderConfig> byAlias(final List<IdentityProviderConfig> configs) {
        final Map<String, IdentityProviderConfig> byAlias = new HashMap<>();
        configs.forEach(c -> byAlias.put(c.alias(), c));
        return byAlias;
    }

    private void remember(final String realmId, final List<IdentityProviderConfig> configs) {
        if (configs.isEmpty()) {
            loaded.remove(realmId);
        } else {
            loaded.put(realmId, byAlias(configs));
        }
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
