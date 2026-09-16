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
 */
class FederationStoreRefresherTest {

    private final FederationProviderFactory factory = new FederationProviderFactory(
            mock(OidcTokenClient.class), mock(SamlAssertionValidator.class), mock(EidAssertionValidator.class),
            mock(io.helixiam.authorization.federation.eid.EidArtifactResolver.class));

    private static IdentityProviderConfig oidc(final String alias, final boolean enabled) {
        return new IdentityProviderConfig("gov", alias, "oidc", alias, enabled,
                Map.of("clientId", "cid", "clientSecret", "sec",
                        "authorizationEndpoint", "https://idp/authorize", "tokenEndpoint", "https://idp/token",
                        "jwksUri", "https://idp/jwks", "issuer", "https://idp", "scopes", "openid"));
    }

    @Test
    void refresh_loadsEnabledStoredProvidersIntoTheRegistry() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(
                realm -> List.of(oidc("digid", true), oidc("corp", true)), factory, registry);

        final int loaded = refresher.refresh("gov");

        assertThat(loaded).isEqualTo(2);
        assertThat(registry.aliases()).contains("digid", "corp");
    }

    @Test
    void refresh_skipsDisabledConnections() {
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(
                realm -> List.of(oidc("live", true), oidc("draft", false)), factory, registry);

        refresher.refresh("gov");

        assertThat(registry.aliases()).contains("live");
        assertThat(registry.aliases()).doesNotContain("draft");
    }

    @Test
    void refresh_skipsAMalformedConnectionWithoutFailingTheRest() {
        final IdentityProviderConfig broken = new IdentityProviderConfig("gov", "oops", "carrier-pigeon", "Oops", true, Map.of());
        final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
        final FederationStoreRefresher refresher = new FederationStoreRefresher(
                realm -> List.of(oidc("ok", true), broken), factory, registry);

        final int loaded = refresher.refresh("gov");

        assertThat(loaded).isEqualTo(1);
        assertThat(registry.aliases()).contains("ok");
        assertThat(registry.aliases()).doesNotContain("oops");
    }
}
