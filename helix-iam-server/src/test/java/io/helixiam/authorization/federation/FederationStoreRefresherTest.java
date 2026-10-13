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

    // --- every replica follows the store: a change made on another replica (or by a realm import) goes live ----------

    /** A store whose content a test changes, like another replica's admin write does. */
    private static final class MutableStore implements IdentityProviderConfigSource {
        private volatile List<IdentityProviderConfig> configs;

        MutableStore(final List<IdentityProviderConfig> configs) {
            this.configs = configs;
        }

        @Override
        public List<IdentityProviderConfig> load(final String realmId) {
            return configs.stream().filter(c -> c.realmId().equals(realmId)).toList();
        }

        @Override
        public List<IdentityProviderConfig> loadAll() {
            return configs;
        }
    }

    @Test
    void refreshChanged_dropsAConnectionDisabledElsewhere_andLeavesUnchangedRealmsAlone() {
        final MutableStore store = new MutableStore(List.of(oidc("gov", "corp", true), oidc("acme", "okta", true)));
        final IdentityProviderRegistry registry = org.mockito.Mockito.spy(new IdentityProviderRegistry(List.of()));
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store, factory, registry);
        refresher.refreshAll();
        assertThat(registry.aliases("gov")).contains("corp");

        store.configs = List.of(oidc("gov", "corp", false), oidc("acme", "okta", true)); // disabled on another replica

        assertThat(refresher.refreshChanged()).isEqualTo(1);
        assertThat(registry.aliases("gov")).doesNotContain("corp");
        assertThat(registry.aliases("acme")).contains("okta");
        org.mockito.Mockito.verify(registry, org.mockito.Mockito.never())
                .reload(org.mockito.ArgumentMatchers.eq("acme"), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void refreshChanged_dropsADeletedRealmsConnections_andPicksUpANewOne() {
        final MutableStore store = new MutableStore(List.of(oidc("gov", "corp", true)));
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store, factory, registry);
        refresher.refreshAll();

        store.configs = List.of(oidc("acme", "okta", true)); // gov's connection deleted, acme's imported

        assertThat(refresher.refreshChanged()).isEqualTo(2);
        assertThat(registry.aliases("gov")).doesNotContain("corp");
        assertThat(registry.aliases("acme")).contains("okta");
        assertThat(refresher.refreshChanged()).as("nothing changed since").isZero();
    }

    @Test
    void refreshChanged_seesASecretRotatedElsewhere() {
        final MutableStore store = new MutableStore(List.of(oidc("gov", "corp", true)));
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(store, factory, registry);
        refresher.refreshAll();
        final java.util.Map<String, String> rotated = new java.util.HashMap<>(oidc("gov", "corp", true).config());
        rotated.put("clientSecret", "rotated");
        store.configs = List.of(new IdentityProviderConfig("gov", "corp", "oidc", "corp", true, rotated));

        assertThat(refresher.refreshChanged()).isEqualTo(1);
    }
}
