/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation;

import io.helixiam.authorization.federation.eid.EidArtifactResolver;
import io.helixiam.authorization.federation.eid.EidAssertionValidator;
import io.helixiam.authorization.federation.eid.EidProviderConfig;
import io.helixiam.authorization.federation.eid.EidScheme;
import io.helixiam.authorization.federation.oidc.OidcProviderConfig;
import io.helixiam.authorization.federation.oidc.OidcTokenClient;
import io.helixiam.authorization.federation.saml.SamlAssertionValidator;
import io.helixiam.authorization.federation.saml.SamlProviderConfig;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.federation.wallet.WalletConfigValidator;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletIdentityProviders;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Helix IAM E5.4: the factory turns declarative federation config into runtime {@link IdentityProvider}
 * beans — generic OIDC, social presets (Google/Microsoft, which only need a client id + secret), and
 * SAML2 — so adding a provider is configuration, not code. An unknown social preset is rejected.
 */
class FederationProviderFactoryTest {

    private final OidcTokenClient tokenClient = mock(OidcTokenClient.class);
    private final SamlAssertionValidator samlValidator = mock(SamlAssertionValidator.class);
    private final EidAssertionValidator eidValidator = mock(EidAssertionValidator.class);
    private final EidArtifactResolver eidArtifactResolver = mock(EidArtifactResolver.class);
    // EUDI wallet (Task 19): an access key in "master" (YAML providers) and "acme" (a stored provider's realm).
    private static final TestPki ACCESS_PKI = TestPki.create("Factory Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestPki PID_ISSUERS = TestPki.create("Factory PID Provider");
    private final TestAccessKeys accessKeys = new TestAccessKeys(ACCESS, "eudi-access", "master", "acme");
    private final WalletIdentityProviders walletProviders = new WalletIdentityProviders(
            new WalletConfigValidator(accessKeys, DeploymentProfile.production()), accessKeys,
            new InMemoryWalletTransactionStore(), new OutboundUrlGuard(), mock(AuditLog.class));
    private final FederationProviderFactory factory = new FederationProviderFactory(tokenClient, samlValidator,
            eidValidator, eidArtifactResolver, walletProviders);

    @Test
    void buildsGenericOidcSocialAndSamlProviders() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setOidc(List.of(new OidcProviderConfig("acme", "ACME", "cid", "secret",
                "https://idp/authorize", "https://idp/token", "https://idp/jwks", "https://idp", List.of("openid"))));
        props.setSocial(List.of(new FederationProviderProperties.SocialEntry("google", "g-id", "g-secret", null)));
        props.setSaml(List.of(new SamlProviderConfig("corp", "Corp", "https://idp/sso", "https://idp/entity",
                "https://helix/sp", "https://helix/acs", "PEM", "mail", "givenName", "sn")));

        final List<IdentityProvider> providers = factory.build(props);

        assertThat(providers).extracting(p -> p.metadata().alias())
                .containsExactlyInAnyOrder("acme", "google", "corp");
        assertThat(providers).extracting(p -> p.metadata().protocol())
                .containsExactlyInAnyOrder(IdpMetadata.Protocol.OIDC, IdpMetadata.Protocol.OIDC, IdpMetadata.Protocol.SAML2);
    }

    @Test
    void buildsTheMicrosoftSocialPresetWithItsTenant() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setSocial(List.of(new FederationProviderProperties.SocialEntry("microsoft", "m-id", "m-secret", "common")));

        final List<IdentityProvider> providers = factory.build(props);

        assertThat(providers).hasSize(1);
        assertThat(providers.get(0).metadata().alias()).isEqualTo("microsoft");
    }

    @Test
    void rejectsAnUnknownSocialPreset() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setSocial(List.of(new FederationProviderProperties.SocialEntry("myspace", "id", "secret", null)));

        assertThatThrownBy(() -> factory.build(props)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildsAnEidConnectorFromConfig() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setEid(List.of(new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD", "https://digid/sso",
                "https://digid/entity", "https://helix/sp", "https://helix/acs", "idp-cert", "sp-key",
                "sp-sign-key", "sp-cert", "urn:loa", "bsn")));

        final List<IdentityProvider> providers = factory.build(props);

        assertThat(providers).hasSize(1);
        assertThat(providers.get(0).metadata().alias()).isEqualTo("digid");
        assertThat(providers.get(0).metadata().protocol()).isEqualTo(IdpMetadata.Protocol.SAML2);
    }

    @Test
    void emptyConfigYieldsNoProviders() {
        assertThat(factory.build(new FederationProviderProperties())).isEmpty();
    }

    // --- E8.3: build a live provider from a stored (admin-managed) config ---

    @Test
    void fromStored_buildsAnOidcProvider() {
        final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored =
                new io.helixiam.authorization.amqp.federation.IdentityProviderConfig("gov", "acme", "oidc", "ACME", true,
                        java.util.Map.of("clientId", "cid", "clientSecret", "sec",
                                "authorizationEndpoint", "https://idp/authorize", "tokenEndpoint", "https://idp/token",
                                "jwksUri", "https://idp/jwks", "issuer", "https://idp", "scopes", "openid email"));

        final IdentityProvider provider = factory.fromStored(stored);

        assertThat(provider.metadata().alias()).isEqualTo("acme");
        assertThat(provider.metadata().displayName()).isEqualTo("ACME");
        assertThat(provider.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.OIDC);
    }

    @Test
    void fromStored_buildsASamlProvider() {
        final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored =
                new io.helixiam.authorization.amqp.federation.IdentityProviderConfig("gov", "corp", "saml", "Corp SSO", true,
                        java.util.Map.of("ssoUrl", "https://idp/sso", "idpEntityId", "https://idp/entity",
                                "spEntityId", "https://helix/sp", "assertionConsumerServiceUrl", "https://helix/acs",
                                "idpSigningCertificate", "PEM"));

        final IdentityProvider provider = factory.fromStored(stored);

        assertThat(provider.metadata().alias()).isEqualTo("corp");
        assertThat(provider.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.SAML2);
    }

    @Test
    void fromStored_buildsAnEidProvider_fromTheSchemeProtocol() {
        final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored =
                new io.helixiam.authorization.amqp.federation.IdentityProviderConfig("gov", "digid", "digid", "DigiD", true,
                        java.util.Map.of("ssoUrl", "https://digid/sso", "idpEntityId", "https://digid/entity",
                                "spEntityId", "https://helix/sp", "assertionConsumerServiceUrl", "https://helix/acs",
                                "minimumLoa", "urn:nl-eid-gdi:1.0:LoA:Substantieel", "subjectAttribute", "bsn"));

        final IdentityProvider provider = factory.fromStored(stored);

        assertThat(provider.metadata().alias()).isEqualTo("digid");
        assertThat(provider.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.SAML2);
    }

    @Test
    void fromStored_rejectsAnUnknownProtocol() {
        final io.helixiam.authorization.amqp.federation.IdentityProviderConfig stored =
                new io.helixiam.authorization.amqp.federation.IdentityProviderConfig("gov", "x", "carrier-pigeon", "X", true,
                        java.util.Map.of());

        assertThatThrownBy(() -> factory.fromStored(stored)).isInstanceOf(IllegalArgumentException.class);
    }

    // ------------------------------------------------------------------ EUDI wallet (Task 19)

    private Map<String, String> walletSettings(final String realm) {
        final Map<String, String> m = new HashMap<>();
        m.put("accessKeyRef", accessKeys.ref(realm));
        m.put("trustAnchors", PID_ISSUERS.rootPem());
        return m;
    }

    @Test
    void buildsAWalletProviderFromYamlWithItsKeyInTheMasterRealm() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setWallet(List.of(WalletProviderConfig.fromStored("eudi-wallet", "EUDI Wallet", walletSettings("master"))));

        final List<IdentityProvider> providers = factory.build(props);

        assertThat(providers).singleElement().satisfies(p -> {
            assertThat(p.metadata().alias()).isEqualTo("eudi-wallet");
            assertThat(p.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.WALLET);
            assertThat(p.metadata().iconKey()).isEqualTo("eudi-wallet");
            assertThat(WalletIdentityProvider.from(p)).isPresent();
        });
    }

    @Test
    void anInvalidYamlWalletProviderIsSkippedAndTheOthersStillBuild() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setOidc(List.of(new OidcProviderConfig("acme", "ACME", "cid", "secret",
                "https://idp/authorize", "https://idp/token", "https://idp/jwks", "https://idp", List.of("openid"))));
        final Map<String, String> invalid = walletSettings("master");
        invalid.put("transactionTtlSeconds", "5");
        final Map<String, String> foreignKey = walletSettings("acme"); // YAML resolves in master only
        props.setWallet(List.of(WalletProviderConfig.fromStored("bad-wallet", "Bad", invalid),
                WalletProviderConfig.fromStored("acme-key-wallet", "Wrong realm", foreignKey)));

        assertThat(factory.build(props)).extracting(p -> p.metadata().alias()).containsExactly("acme");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"eudi-wallet", "openid4vp", "wallet", "OpenID4VP"})
    void fromStored_buildsAWalletProviderForEveryWalletProtocol(final String protocol) {
        final var stored = new io.helixiam.authorization.amqp.federation.IdentityProviderConfig(
                "acme", "my-wallet", protocol, "Sign in with your wallet", true, walletSettings("acme"));

        final IdentityProvider provider = factory.fromStored(stored);

        assertThat(provider.metadata().alias()).isEqualTo("my-wallet");
        assertThat(provider.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.WALLET);
        assertThat(provider.metadata().displayName()).isEqualTo("Sign in with your wallet");
        assertThat(provider.metadata().iconKey()).isEqualTo("eudi-wallet");
        assertThat(WalletIdentityProvider.from(provider)).isPresent();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {" wallet ", "EUDI-WALLET", "\tOpenID4VP"})
    void fromStored_normalisesAPaddedOrUpperCaseProtocolLikeIsWallet(final String protocol) {
        final var stored = new io.helixiam.authorization.amqp.federation.IdentityProviderConfig(
                "acme", "my-wallet", protocol, "Wallet", true, walletSettings("acme"));

        assertThat(FederationProviderFactory.isWallet(protocol)).isTrue();
        final IdentityProvider provider = factory.fromStored(stored);
        assertThat(provider.metadata().protocol()).isEqualTo(IdpMetadata.Protocol.WALLET);
        assertThat(provider.metadata().iconKey()).isEqualTo("eudi-wallet");
        assertThat(WalletIdentityProvider.from(provider).orElseThrow().keyRealm()).isEqualTo("acme");
    }

    @Test
    void fromYaml_aWalletProviderIsNotBoundToARealm() {
        final FederationProviderProperties props = new FederationProviderProperties();
        props.setWallet(List.of(WalletProviderConfig.fromStored("eudi-wallet", "EUDI Wallet", walletSettings("master"))));

        assertThat(WalletIdentityProvider.from(factory.build(props).get(0)).orElseThrow().keyRealm()).isNull();
    }

    @Test
    void fromStored_anInvalidWalletConfigThrowsSoTheRefresherSkipsIt() {
        final Map<String, String> settings = walletSettings("acme");
        settings.put("credentialFormats", "not a list");
        final var stored = new io.helixiam.authorization.amqp.federation.IdentityProviderConfig(
                "acme", "my-wallet", "eudi-wallet", "Wallet", true, settings);

        assertThatThrownBy(() -> factory.fromStored(stored)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("credentialFormats");
    }

    @Test
    void fromStored_aWalletKeyRefIsResolvedInTheProvidersOwnRealm() {
        final var stored = new io.helixiam.authorization.amqp.federation.IdentityProviderConfig(
                "acme", "my-wallet", "eudi-wallet", "Wallet", true, walletSettings("master"));

        assertThatThrownBy(() -> factory.fromStored(stored)).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("accessKeyRef");
    }

    @Test
    void inferIconKey_isTheNeutralWalletMarkForWalletProtocols() {
        assertThat(FederationProviderFactory.inferIconKey("eudi-wallet", "w", "W")).isEqualTo("eudi-wallet");
        assertThat(FederationProviderFactory.inferIconKey("openid4vp", "w", "W")).isEqualTo("eudi-wallet");
        assertThat(FederationProviderFactory.inferIconKey("wallet", "w", "W")).isEqualTo("eudi-wallet");
        assertThat(FederationProviderFactory.inferIconKey("wallet", "digid-wallet", "DigiD wallet"))
                .isEqualTo("eudi-wallet");
    }
}
