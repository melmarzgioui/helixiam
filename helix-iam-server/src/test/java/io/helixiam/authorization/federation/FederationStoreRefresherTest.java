/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.federation.eid.EidAssertionValidator;
import io.helixiam.authorization.federation.oidc.OidcTokenClient;
import io.helixiam.authorization.federation.saml.SamlAssertionValidator;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Helix IAM E8.3: the registry's providers come from the persisted store at runtime — a connection
 * created in the admin console (E8.2) becomes loginable after a refresh, without a restart. Disabled
 * connections are skipped; a malformed one is logged and skipped without sinking the whole refresh.
 *
 * <p>Final review F1: the startup load covers every realm, and a write in one realm refreshes only that realm.
 */
class FederationStoreRefresherTest {

    private final FederationProviderFactory factory = new FederationProviderFactory(
            mock(OidcTokenClient.class), mock(SamlAssertionValidator.class), mock(EidAssertionValidator.class),
            mock(io.helixiam.authorization.federation.eid.EidArtifactResolver.class),
            mock(io.helixiam.authorization.federation.wallet.WalletIdentityProviders.class));

    private static IdentityProviderConfig oidc(final String alias, final boolean enabled) {
        return oidc("gov", alias, enabled);
    }

    private static IdentityProviderConfig oidc(final String realm, final String alias, final boolean enabled) {
        return new IdentityProviderConfig(realm, alias, "oidc", alias, enabled,
                Map.of("clientId", "cid", "clientSecret", "sec",
                        "authorizationEndpoint", "https://idp/authorize", "tokenEndpoint", "https://idp/token",
                        "jwksUri", "https://idp/jwks", "issuer", "https://idp", "scopes", "openid"));
    }

    /** A store holding {@code configs}, across their realms. */
    private static IdentityProviderConfigSource store(final List<IdentityProviderConfig> configs) {
        return new IdentityProviderConfigSource() {
            @Override
            public List<IdentityProviderConfig> load(final String realmId) {
                return configs.stream().filter(c -> c.realmId().equals(realmId)).toList();
            }

            @Override
            public List<IdentityProviderConfig> loadAll() {
                return configs;
            }
        };
    }

    @Test
    void refresh_loadsEnabledStoredProvidersIntoTheRegistry() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(
                realm -> List.of(oidc("digid", true), oidc("corp", true)), factory, registry);

        final int loaded = refresher.refresh("gov");

        assertThat(loaded).isEqualTo(2);
        assertThat(registry.aliases("gov")).contains("digid", "corp");
    }

    @Test
    void refresh_skipsDisabledConnections() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(
                realm -> List.of(oidc("live", true), oidc("draft", false)), factory, registry);

        refresher.refresh("gov");

        assertThat(registry.aliases("gov")).contains("live");
        assertThat(registry.aliases("gov")).doesNotContain("draft");
    }

    @Test
    void refresh_skipsAMalformedConnectionWithoutFailingTheRest() {
        final IdentityProviderConfig broken = new IdentityProviderConfig("gov", "oops", "carrier-pigeon", "Oops", true, Map.of());
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(
                realm -> List.of(oidc("ok", true), broken), factory, registry);

        final int loaded = refresher.refresh("gov");

        assertThat(loaded).isEqualTo(1);
        assertThat(registry.aliases("gov")).contains("ok");
        assertThat(registry.aliases("gov")).doesNotContain("oops");
    }

    @Test
    void refreshAll_loadsEveryRealm_eachUnderItsOwnRealm() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store(List.of(
                oidc("realm-a", "shared", true), oidc("realm-b", "shared", true), oidc("realm-b", "only-b", true))),
                factory, registry);

        final int loaded = refresher.refreshAll();

        assertThat(loaded).isEqualTo(3);
        assertThat(registry.aliases("realm-a")).containsExactly("shared");
        assertThat(registry.aliases("realm-b")).containsExactlyInAnyOrder("shared", "only-b");
        assertThat(registry.get("realm-a", "shared")).isNotSameAs(registry.get("realm-b", "shared"));
    }

    @Test
    void refreshOfRealmB_leavesRealmALoaded() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store(List.of(
                oidc("realm-a", "corp-a", true), oidc("realm-b", "corp-b", true))), factory, registry);
        refresher.refreshAll();

        refresher.refresh("realm-b");

        assertThat(registry.aliases("realm-a")).containsExactly("corp-a");
        assertThat(registry.aliases("realm-b")).containsExactly("corp-b");
    }

    // ---- production readiness item 1: versions, cross-replica polling and version-ordered publication ----

    /** A store whose configs and per-realm versions the test changes, as another replica's admin write would. */
    private static class VersionedStore implements IdentityProviderConfigSource {
        final Map<String, List<IdentityProviderConfig>> configs = new ConcurrentHashMap<>();
        final Map<String, Long> versions = new ConcurrentHashMap<>();
        final AtomicInteger loads = new AtomicInteger();

        void write(final String realm, final long version, final IdentityProviderConfig... realmConfigs) {
            configs.put(realm, List.of(realmConfigs));
            versions.put(realm, version);
        }

        @Override
        public List<IdentityProviderConfig> load(final String realmId) {
            loads.incrementAndGet();
            return configs.getOrDefault(realmId, List.of());
        }

        @Override
        public List<IdentityProviderConfig> loadAll() {
            return configs.values().stream().flatMap(List::stream).toList();
        }

        @Override
        public Map<String, Long> versions() {
            return Map.copyOf(versions);
        }
    }

    @Test
    void refreshChanged_refreshesOnlyTheRealmsWhoseVersionMoved() {
        final VersionedStore store = new VersionedStore();
        store.write("realm-a", 1, oidc("realm-a", "a1", true));
        store.write("realm-b", 1, oidc("realm-b", "b1", true));
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store, factory, registry);
        refresher.refreshAll();
        store.loads.set(0);

        assertThat(refresher.refreshChanged()).as("nothing moved").isZero();
        assertThat(store.loads.get()).isZero();

        store.write("realm-b", 2, oidc("realm-b", "b2", true)); // another replica's write
        store.write("realm-c", 1, oidc("realm-c", "c1", true)); // a realm that had nothing at startup

        assertThat(refresher.refreshChanged()).isEqualTo(2);
        assertThat(registry.aliases("realm-a")).containsExactly("a1");
        assertThat(registry.aliases("realm-b")).containsExactly("b2");
        assertThat(registry.aliases("realm-c")).containsExactly("c1");
        assertThat(refresher.refreshChanged()).as("converged").isZero();
    }

    @Test
    void twoConcurrentRefreshes_neverPublishTheOlderSetOverTheNewer() throws Exception {
        final AtomicReference<CountDownLatch> holdNextLoad = new AtomicReference<>(new CountDownLatch(1));
        final CountDownLatch slowLoadStarted = new CountDownLatch(1);
        final VersionedStore store = new VersionedStore() {
            @Override
            public List<IdentityProviderConfig> load(final String realmId) {
                final List<IdentityProviderConfig> snapshot = super.load(realmId);
                final CountDownLatch hold = holdNextLoad.getAndSet(null);
                if (hold != null) { // the first refresh read the old set, then stalls before publishing it
                    slowLoadStarted.countDown();
                    try {
                        hold.await(5, TimeUnit.SECONDS);
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return snapshot;
            }
        };
        store.write("gov", 1, oidc("gov", "old", true));
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store, factory, registry);
        final CountDownLatch release = holdNextLoad.get();

        final ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            final Future<Integer> slow = pool.submit(() -> refresher.refresh("gov"));
            assertThat(slowLoadStarted.await(5, TimeUnit.SECONDS)).isTrue();

            store.write("gov", 2, oidc("gov", "new", true)); // a second write commits...
            refresher.refresh("gov");                          // ...and its refresh publishes first
            release.countDown();                               // then the stale refresh tries to publish
            slow.get(5, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        assertThat(registry.aliases("gov")).containsExactly("new");
        assertThat(registry.version("gov")).isEqualTo(2);
    }
}
