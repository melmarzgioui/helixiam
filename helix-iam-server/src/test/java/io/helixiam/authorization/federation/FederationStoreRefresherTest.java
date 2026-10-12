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
}
