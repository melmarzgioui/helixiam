/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Helix IAM E5.1: identity providers are auto-discovered and routed by alias — the same drop-in SPI
 * shape as the authenticator/credential/attestation registries. Duplicate aliases are rejected.
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

    @Test
    void routesToTheProviderByAlias() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google"), stub("github")));

        assertThat(registry.get("google").metadata().alias()).isEqualTo("google");
        assertThat(registry.aliases()).containsExactlyInAnyOrder("google", "github");
    }

    @Test
    void unknownAliasThrows() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google")));
        assertThatThrownBy(() -> registry.get("ghost")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void duplicateAliasIsRejectedAtStartup() {
        assertThatThrownBy(() -> new IdentityProviderRegistry(List.of(stub("google"), stub("google"))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void emptyRegistryIsAllowed() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        assertThat(registry.aliases()).isEmpty();
    }

    @Test
    void exposesProviderMetadataForTheLoginPage() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("google"), stub("github")));

        assertThat(registry.metadatas()).extracting(IdpMetadata::alias)
                .containsExactly("google", "github"); // insertion order preserved
    }

    // --- E8.3: runtime reload from the persisted store ---

    @Test
    void reload_registersDynamicProvidersAlongsideTheStaticOnes() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("static-a", "A")));

        registry.reload(List.of(stub("dyn-b", "B")));

        assertThat(registry.aliases()).contains("static-a", "dyn-b");
        assertThat(registry.get("dyn-b").metadata().displayName()).isEqualTo("B");
        assertThat(registry.get("static-a").metadata().alias()).isEqualTo("static-a");
    }

    @Test
    void reload_replacesThePreviousDynamicSet_keepingStaticProviders() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("static-a", "A")));

        registry.reload(List.of(stub("dyn-b", "B")));
        registry.reload(List.of(stub("dyn-c", "C")));

        assertThat(registry.aliases()).contains("static-a", "dyn-c");
        assertThat(registry.aliases()).doesNotContain("dyn-b");
    }

    @Test
    void reload_dynamicProviderOverridesAStaticOneOnTheSameAlias() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of(stub("digid", "Old DigiD")));

        registry.reload(List.of(stub("digid", "Stored DigiD")));

        assertThat(registry.get("digid").metadata().displayName()).isEqualTo("Stored DigiD");
    }
}
