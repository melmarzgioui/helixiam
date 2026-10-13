/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E5.1: identity providers are auto-discovered and routed by alias — the same drop-in SPI
 * shape as the authenticator/credential/attestation registries. Duplicate aliases are rejected.
 *
 * <p>Final review F1: store-backed providers are keyed by (realm, alias). A reload replaces one realm's set and leaves
 * every other realm's alone; static (bean / YAML) providers serve every realm.
 */
class IdentityProviderRegistryTest {

    private static IdentityProvider stub(final String alias) {
        return stub(alias, alias);
    }

    private static IdentityProvider stub(final String alias, final String displayName) {
        return new IdentityProvider() {
            @Override public IdpMetadata metadata() { return IdpMetadata.of(alias, IdpMetadata.Protocol.OIDC, displayName); }
            @Override public RedirectResponse start(final AuthnRequestContext c) { return new RedirectResponse("/" + alias, java.util.Map.of()); }
            @Override public BrokeredIdentity callback(final CallbackContext c) { return new BrokeredIdentity(alias, "s", null, false, java.util.Map.of()); }
            @Override public void logout(final LogoutContext c) { }
        };
    }

    /** A wallet provider bound to {@code realm} ({@code null}: a YAML provider, every realm). */
    private static WalletIdentityProvider wallet(final String alias, final String realm) {
        final WalletIdentityProvider wallet = mock(WalletIdentityProvider.class);
        when(wallet.metadata()).thenReturn(IdpMetadata.of(alias, IdpMetadata.Protocol.OIDC, "Wallet " + realm));
        when(wallet.servesRealm(any()))
                .thenAnswer(inv -> inv.getArgument(0) != null && (realm == null || realm.equals(inv.getArgument(0))));
        return wallet;
    }

    @Test
    void routesToTheProviderByAlias() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google"), stub("github")));

        assertThat(registry.get("any", "google").metadata().alias()).isEqualTo("google");
        assertThat(registry.aliases("any")).containsExactlyInAnyOrder("google", "github");
    }

    @Test
    void unknownAliasThrows() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google")));
        assertThatThrownBy(() -> registry.get("any", "ghost")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void duplicateAliasIsRejectedAtStartup() {
        assertThatThrownBy(() -> new IdentityProviderRegistry(List.of(stub("google"), stub("google"))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void emptyRegistryIsAllowed() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        assertThat(registry.aliases("any")).isEmpty();
    }

    @Test
    void exposesProviderMetadataForTheLoginPage() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google"), stub("github")));

        assertThat(registry.metadatas("any")).extracting(IdpMetadata::alias)
                .containsExactly("google", "github"); // insertion order preserved
    }

    // --- E8.3: runtime reload from the persisted store ---

    @Test
    void reload_registersDynamicProvidersAlongsideTheStaticOnes() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("static-a", "A")));

        registry.reload("gov", List.of(stub("dyn-b", "B")));

        assertThat(registry.aliases("gov")).contains("static-a", "dyn-b");
        assertThat(registry.get("gov", "dyn-b").metadata().displayName()).isEqualTo("B");
        assertThat(registry.get("gov", "static-a").metadata().alias()).isEqualTo("static-a");
    }

    @Test
    void reload_replacesThePreviousDynamicSetOfThatRealm_keepingStaticProviders() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("static-a", "A")));

        registry.reload("gov", List.of(stub("dyn-b", "B")));
        registry.reload("gov", List.of(stub("dyn-c", "C")));

        assertThat(registry.aliases("gov")).contains("static-a", "dyn-c");
        assertThat(registry.aliases("gov")).doesNotContain("dyn-b");
    }

    @Test
    void reload_dynamicProviderOverridesAStaticOneOnTheSameAlias_inItsOwnRealmOnly() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("digid", "Old DigiD")));

        registry.reload("gov", List.of(stub("digid", "Stored DigiD")));

        assertThat(registry.get("gov", "digid").metadata().displayName()).isEqualTo("Stored DigiD");
        assertThat(registry.get("other", "digid").metadata().displayName()).isEqualTo("Old DigiD");
    }

    // --- Final review F1: per-realm store-backed providers ---

    @Test
    void reloadOfOneRealm_leavesEveryOtherRealmLoaded() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("realm-a", List.of(stub("corp-a")));

        registry.reload("realm-b", List.of(stub("corp-b")));

        assertThat(registry.aliases("realm-a")).containsExactly("corp-a");
        assertThat(registry.aliases("realm-b")).containsExactly("corp-b");
        assertThat(registry.get("realm-a", "corp-a").metadata().alias()).isEqualTo("corp-a");
    }

    @Test
    void theSameAliasInTwoRealms_resolvesToEachRealmsOwnProvider() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final WalletIdentityProvider walletA = wallet("eudi-wallet", "realm-a");
        final WalletIdentityProvider walletB = wallet("eudi-wallet", "realm-b");

        registry.reload("realm-a", List.of(walletA));
        registry.reload("realm-b", List.of(walletB));

        assertThat(registry.get("realm-a", "eudi-wallet")).isSameAs(walletA);
        assertThat(registry.get("realm-b", "eudi-wallet")).isSameAs(walletB);
        assertThat(registry.named("eudi-wallet")).containsExactlyInAnyOrder(walletA, walletB);
    }

    @Test
    void aStoredProviderOfAnotherRealm_isNotListedOrResolved() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google")));
        registry.reload("realm-b", List.of(wallet("eudi-b", "realm-b")));

        assertThat(registry.metadatas("realm-a")).extracting(IdpMetadata::alias).containsExactly("google");
        assertThatThrownBy(() -> registry.get("realm-a", "eudi-b")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aProviderThatDoesNotServeTheRealm_isNeverListedOrResolvedThere() {
        // Defence in depth: a realm-bound wallet among the static providers (or in another realm's set) is filtered by
        // its own servesRealm.
        final WalletIdentityProvider foreign = wallet("eudi-x", "realm-b");
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(foreign));

        assertThat(registry.metadatas("realm-a")).isEmpty();
        assertThatThrownBy(() -> registry.get("realm-a", "eudi-x")).isInstanceOf(IllegalArgumentException.class);
        assertThat(registry.get("realm-b", "eudi-x")).isSameAs(foreign);
    }

    @Test
    void aYamlWalletProvider_servesEveryRealm() {
        final WalletIdentityProvider yaml = wallet("eudi-yaml", null);
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(yaml));

        assertThat(registry.metadatas("realm-a")).extracting(IdpMetadata::alias).containsExactly("eudi-yaml");
        assertThat(registry.get("realm-b", "eudi-yaml")).isSameAs(yaml);
    }

    @Test
    void replaceAll_swapsEveryRealmsStoreBackedSet() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("stale", List.of(stub("gone")));

        registry.replaceAll(Map.of("realm-a", List.of(stub("a")), "realm-b", List.of(stub("b"))));

        assertThat(registry.aliases("stale")).isEmpty();
        assertThat(registry.aliases("realm-a")).containsExactly("a");
        assertThat(registry.aliases("realm-b")).containsExactly("b");
    }

    @Test
    void aNullRealm_seesOnlyTheStaticProviders() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google")));
        registry.reload("realm-a", List.of(stub("corp")));

        assertThat(registry.aliases(null)).containsExactly("google");
        assertThatThrownBy(() -> registry.get(null, "corp")).isInstanceOf(IllegalArgumentException.class);
    }

    // ---- production readiness item 1: version-ordered publication ----

    @Test
    void aVersionedReload_neverPublishesAnOlderVersionOverANewerOne() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        assertThat(registry.reload("realm-a", List.of(stub("newer")), 2)).isTrue();

        assertThat(registry.reload("realm-a", List.of(stub("older")), 1)).isFalse();

        assertThat(registry.aliases("realm-a")).containsExactly("newer");
        assertThat(registry.version("realm-a")).isEqualTo(2);
    }

    @Test
    void aVersionedReload_ofTheSameOrANewerVersion_isPublished() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("realm-a", List.of(stub("one")), 3);

        assertThat(registry.reload("realm-a", List.of(stub("same")), 3)).isTrue();
        assertThat(registry.aliases("realm-a")).containsExactly("same");
        assertThat(registry.reload("realm-a", List.of(), 4)).isTrue();
        assertThat(registry.aliases("realm-a")).isEmpty();
        assertThat(registry.version("realm-a")).as("an emptied realm keeps its version").isEqualTo(4);
    }

    @Test
    void replaceAll_setsEveryRealmsVersion_andAnUnknownRealmIsAtVersionZero() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("stale", List.of(stub("gone")), 9);

        registry.replaceAll(Map.of("realm-a", List.of(stub("a"))), Map.of("realm-a", 5L, "realm-b", 2L));

        assertThat(registry.version("realm-a")).isEqualTo(5);
        assertThat(registry.version("realm-b")).isEqualTo(2);
        assertThat(registry.version("stale")).isZero();
        assertThat(registry.reload("realm-a", List.of(stub("old")), 4)).isFalse();
    }

    @Test
    void replaceAll_keepsARealmPublishedAtANewerVersionThanTheSnapshot() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("realm-a", List.of(stub("newer")), 7); // a refresh that overtook the startup load

        registry.replaceAll(Map.of("realm-a", List.of(stub("snapshot"))), Map.of("realm-a", 5L));

        assertThat(registry.aliases("realm-a")).containsExactly("newer");
        assertThat(registry.version("realm-a")).isEqualTo(7);
    }

    @Test
    void isWallet_asksTheRealmsOwnProviderFirst_andOtherwiseEveryRealm() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        registry.reload("realm-a", List.of(stub("corp")));
        registry.reload("realm-b", List.of(wallet("corp", "realm-b")));

        assertThat(registry.isWallet("realm-a", "corp")).as("realm A's own OIDC connection decides").isFalse();
        assertThat(registry.isWallet("realm-b", "corp")).isTrue();
        assertThat(registry.isWallet("realm-c", "corp")).as("not served there: any realm's wallet counts").isTrue();
        assertThat(registry.isWallet("realm-a", null)).isFalse();
    }
}
