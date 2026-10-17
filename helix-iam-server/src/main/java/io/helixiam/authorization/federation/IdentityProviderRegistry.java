/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Helix IAM E5.1: catalogue of {@link IdentityProvider}s, keyed by alias. Assembled in
 * {@link FederationConfig} from auto-discovered {@code @Component} providers plus the ones
 * {@link FederationProviderFactory} builds from {@code helix.federation.*} config (E5.4), so a new
 * connector is either a bean or a config entry. The login page lists the aliases; the broker callback
 * routes by alias. Duplicate aliases are rejected at startup.
 *
 * <p>Two kinds of provider:
 * <ul>
 *   <li><b>static</b> (beans and {@code helix.federation.*} YAML): serve every realm, keyed by alias;</li>
 *   <li><b>store-backed</b> (created through the admin API / console, E8.3): belong to the realm they were saved in,
 *       keyed by (realm, alias). Two realms may use the same alias (the console proposes {@code eudi-wallet} in every
 *       realm); each realm resolves its own. A reload replaces one realm's set and leaves every other realm's alone.</li>
 * </ul>
 * Every lookup is for a realm, and a provider that does not serve that realm (a realm-bound wallet,
 * {@link WalletIdentityProvider#servesRealm}) is never returned or listed there.
 */
public class IdentityProviderRegistry {

    private static final Logger LOG = LogManager.getLogger(IdentityProviderRegistry.class);

    /** Startup providers — bean-discovered + built from {@code helix.federation.*} props (E5.4). */
    private final Map<String, IdentityProvider> staticByAlias = new LinkedHashMap<>();
    /**
     * Store-backed providers per realm (E8.3), each realm's map keyed by alias. Copy-on-write: writers build a new map
     * under the lock and publish it, so a reader sees one realm's old or new set, never a partial one.
     */
    private volatile Map<String, Map<String, IdentityProvider>> dynamicByRealm = Map.of();
    /**
     * The store version (production readiness item 1: {@code idp_config_version}) each realm's published set was read
     * at. A versioned reload older than this is refused, so two refreshes racing (two admin writes, a write and the
     * poll) can never publish the older set over the newer one. A realm without an entry is at version 0.
     */
    private volatile Map<String, Long> versionByRealm = Map.of();

    public IdentityProviderRegistry(final Collection<IdentityProvider> providers) {
        for (final IdentityProvider provider : providers) {
            final String alias = provider.metadata().alias();
            if (staticByAlias.containsKey(alias)) {
                throw new IllegalArgumentException("Duplicate identity provider alias: " + alias);
            }
            staticByAlias.put(alias, provider);
        }
        LOG.info("Helix federation SPI: discovered {} identity provider(s): {}", staticByAlias.size(),
                LogSafe.sanitize(staticByAlias.keySet()));
    }

    /**
     * Replaces the store-backed providers of {@code realmId} with {@code providers} (E8.3), keeping the realm's
     * version; every other realm's set and the static providers are untouched. Within the realm a store-backed provider
     * takes precedence over a static one on the same alias, so an admin-managed connection overrides a config/bean
     * default; within the set the last wins on a duplicate alias. The store refresher uses the versioned
     * {@link #reload(String, Collection, long)}.
     */
    public synchronized void reload(final String realmId, final Collection<IdentityProvider> providers) {
        publish(realmId, providers, version(realmId));
    }

    /**
     * Replaces the store-backed providers of {@code realmId} with {@code providers} read from the store at
     * {@code version}, unless a newer version of the realm is already published (production readiness item 1).
     *
     * @return {@code true} when published; {@code false} when refused as older than the published set
     */
    public synchronized boolean reload(final String realmId, final Collection<IdentityProvider> providers,
                                       final long version) {
        final long published = version(realmId);
        if (version < published) {
            LOG.debug("Helix federation: kept realm {} at version {}; a refresh read at version {} came too late",
                    LogSafe.sanitize(realmId), published, version);
            return false;
        }
        publish(realmId, providers, version);
        return true;
    }

    /** The store version {@code realmId}'s published set was read at (0 when none was). */
    public long version(final String realmId) {
        return realmId == null ? 0L : versionByRealm.getOrDefault(realmId, 0L);
    }

    private void publish(final String realmId, final Collection<IdentityProvider> providers, final long version) {
        if (realmId == null) {
            throw new IllegalArgumentException("A store-backed provider set needs its realm");
        }
        final Map<String, Map<String, IdentityProvider>> next = new LinkedHashMap<>(dynamicByRealm);
        final Map<String, IdentityProvider> realm = byAlias(providers);
        if (realm.isEmpty()) {
            next.remove(realmId);
        } else {
            next.put(realmId, realm);
        }
        this.dynamicByRealm = Map.copyOf(next);
        if (version > 0) {
            final Map<String, Long> versions = new LinkedHashMap<>(versionByRealm);
            versions.put(realmId, version);
            this.versionByRealm = Map.copyOf(versions);
        }
        LOG.info("Helix federation: reloaded {} store-backed identity provider(s) for realm {} at version {}: {}",
                realm.size(), LogSafe.sanitize(realmId), version, LogSafe.sanitize(realm.keySet()));
    }

    /**
     * Replaces every realm's store-backed providers at once and forgets every version: realms absent from the map end
     * empty. What a process restart does; the store refresher's startup load uses {@link #replaceAll(Map, Map)}.
     */
    public synchronized void replaceAll(final Map<String, ? extends Collection<IdentityProvider>> providersByRealm) {
        this.versionByRealm = Map.of();
        replaceAll(providersByRealm, Map.of());
    }

    /**
     * Replaces every realm's store-backed providers with a snapshot of the whole store read at {@code versions} (the
     * startup load): a realm absent from the snapshot ends empty, and a realm already published at a NEWER version
     * than the snapshot's (a refresh that overtook the load) keeps its set.
     */
    public synchronized void replaceAll(final Map<String, ? extends Collection<IdentityProvider>> providersByRealm,
                                        final Map<String, Long> versions) {
        final Map<String, Map<String, IdentityProvider>> next = new LinkedHashMap<>();
        final Map<String, Long> nextVersions = new LinkedHashMap<>();
        providersByRealm.forEach((realmId, providers) -> {
            final Map<String, IdentityProvider> realm = byAlias(providers);
            if (realmId != null && !realm.isEmpty()) {
                next.put(realmId, realm);
            }
        });
        versions.forEach((realmId, version) -> {
            if (realmId == null || version == null) {
                return;
            }
            final long published = version(realmId);
            if (published > version) { // newer than the snapshot: keep it
                final Map<String, IdentityProvider> kept = dynamicByRealm.get(realmId);
                if (kept == null) {
                    next.remove(realmId);
                } else {
                    next.put(realmId, kept);
                }
                nextVersions.put(realmId, published);
            } else if (version > 0) {
                nextVersions.put(realmId, version);
            }
        });
        this.dynamicByRealm = Map.copyOf(next);
        this.versionByRealm = Map.copyOf(nextVersions);
        LOG.info("Helix federation: loaded store-backed identity providers for {} realm(s)", next.size());
    }

    /**
     * The provider {@code alias} of {@code realmId}: the realm's store-backed one, else the static one, and only if it
     * serves the realm. A {@code null} realm (outside a realm-routed request) sees the static providers only.
     *
     * @throws IllegalArgumentException when the realm has no such provider
     */
    public IdentityProvider get(final String realmId, final String alias) {
        final IdentityProvider provider = serving(realmId).get(alias);
        if (provider == null) {
            throw new IllegalArgumentException("No identity provider for alias: " + alias);
        }
        return provider;
    }

    /** The provider aliases {@code realmId} serves (for the login page / admin console). */
    /** Round 6: whether {@code alias} is a static ({@code helix.federation.*}) provider, served in every realm. */
    public boolean isStatic(final String alias) {
        return alias != null && staticByAlias.containsKey(alias);
    }

    public Set<String> aliases(final String realmId) {
        return serving(realmId).keySet();
    }

    /** Metadata (alias + display name + protocol) of the providers {@code realmId} serves, in registration order. */
    public List<IdpMetadata> metadatas(final String realmId) {
        return serving(realmId).values().stream().map(IdentityProvider::metadata).toList();
    }

    /**
     * As {@link #metadatas}, only the providers that can sign a user in ({@link IdentityProvider#signInCapable}): the
     * login page's buttons. An EUDI wallet verify-only connection is never a first factor, so it is never listed.
     */
    public List<IdpMetadata> signInMetadatas(final String realmId) {
        return serving(realmId).values().stream().filter(IdentityProvider::signInCapable)
                .map(IdentityProvider::metadata).toList();
    }

    /**
     * Every registered provider named {@code alias}, of any realm: for code that only has an alias and must answer for
     * whichever realm's provider made a link (links are per user, a user may be in several realms).
     */
    public List<IdentityProvider> named(final String alias) {
        final List<IdentityProvider> found = new ArrayList<>();
        if (alias == null) {
            return found;
        }
        final IdentityProvider fixed = staticByAlias.get(alias);
        if (fixed != null) {
            found.add(fixed);
        }
        for (final Map<String, IdentityProvider> realm : dynamicByRealm.values()) {
            final IdentityProvider stored = realm.get(alias);
            if (stored != null) {
                found.add(stored);
            }
        }
        return found;
    }

    /**
     * Whether {@code alias} names an EU Digital Identity Wallet provider, for code that holds a user's link (production
     * readiness item 5): the provider {@code realmId} serves under that alias decides when there is one, so another
     * realm's wallet with the same alias never turns this realm's OIDC link into a "wallet" link; for an alias the realm
     * does not serve (a link made in another realm, or a provider since removed) any realm's wallet of that alias
     * counts, which keeps a wallet link's HMAC subject out of view (fail safe).
     */
    public boolean isWallet(final String realmId, final String alias) {
        if (alias == null) {
            return false;
        }
        final IdentityProvider own = realmId == null ? null : serving(realmId).get(alias);
        if (own != null) {
            return WalletIdentityProvider.from(own).isPresent();
        }
        return named(alias).stream().anyMatch(p -> WalletIdentityProvider.from(p).isPresent());
    }

    /** Static providers overlaid with {@code realmId}'s store-backed set (store-backed wins), minus any not serving it. */
    private Map<String, IdentityProvider> serving(final String realmId) {
        final Map<String, IdentityProvider> merged = new LinkedHashMap<>(staticByAlias);
        if (realmId != null) {
            merged.putAll(dynamicByRealm.getOrDefault(realmId, Map.of()));
        }
        merged.values().removeIf(provider -> !servesRealm(provider, realmId));
        return merged;
    }

    private static boolean servesRealm(final IdentityProvider provider, final String realmId) {
        return WalletIdentityProvider.from(provider).map(wallet -> wallet.servesRealm(realmId)).orElse(true);
    }

    private static Map<String, IdentityProvider> byAlias(final Collection<IdentityProvider> providers) {
        final Map<String, IdentityProvider> map = new LinkedHashMap<>();
        for (final IdentityProvider provider : providers) {
            map.put(provider.metadata().alias(), provider);
        }
        return map;
    }
}
