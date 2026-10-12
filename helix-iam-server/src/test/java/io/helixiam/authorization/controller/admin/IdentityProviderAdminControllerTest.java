/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import io.helixiam.authorization.amqp.federation.IdentityProviderConfig;
import io.helixiam.authorization.amqp.federation.IdentityProviderConfigPublisher;
import io.helixiam.authorization.amqp.federation.IdentityProviderRef;
import io.helixiam.authorization.federation.wallet.WalletConfigValidator;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM E8.2: admin REST API for identity-provider CRUD. The realm always comes from the path,
 * never the body, so a connection cannot be written into another realm.
 */
class IdentityProviderAdminControllerTest {

    private IdentityProviderConfigPublisher publisher;
    private IdentityProviderAdminController controller;

    @BeforeEach
    void setUp() {
        publisher = mock(IdentityProviderConfigPublisher.class);
        controller = new IdentityProviderAdminController(publisher);
    }

    @Test
    void list_delegatesToPublisherForThatRealm() {
        final IdentityProviderConfig cfg = new IdentityProviderConfig("gov", "digid", "saml", "DigiD", true, Map.of());
        when(publisher.list("gov")).thenReturn(List.of(cfg));

        final List<IdentityProviderAdminView> result = controller.list("gov");

        assertThat(result).containsExactly(IdentityProviderAdminView.of(cfg));
        verify(publisher).list("gov");
    }

    @Test
    void get_returns200_whenPresent_and404_whenAbsent() {
        final IdentityProviderConfig cfg = new IdentityProviderConfig("gov", "digid", "saml", "DigiD", true, Map.of());
        when(publisher.get(new IdentityProviderRef("gov", "digid"))).thenReturn(cfg);
        when(publisher.get(new IdentityProviderRef("gov", "ghost"))).thenReturn(null);

        assertThat(controller.get("gov", "digid").getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(controller.get("gov", "digid").getBody()).isEqualTo(IdentityProviderAdminView.of(cfg));
        assertThat(controller.get("gov", "ghost").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void create_buildsConfigFromPathRealm_ignoringAnyBodyRealm_andReturns201() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        final IdentityProviderRequest body = new IdentityProviderRequest(
                "digid", "saml", "DigiD (CombiConnect)", true, Map.of("ssoUrl", "https://idp"));

        final ResponseEntity<IdentityProviderAdminView> response = controller.create("gov", body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        final ArgumentCaptor<IdentityProviderConfig> captor = ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(publisher).save(captor.capture());
        final IdentityProviderConfig sent = captor.getValue();
        assertThat(sent.realmId()).isEqualTo("gov");
        assertThat(sent.alias()).isEqualTo("digid");
        assertThat(sent.config()).containsEntry("ssoUrl", "https://idp");
    }

    @Test
    void update_usesAliasFromPath_andSaves() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        final IdentityProviderRequest body = new IdentityProviderRequest(
                "ignored-alias", "saml", "DigiD", false, Map.of());

        final ResponseEntity<IdentityProviderAdminView> response = controller.update("gov", "digid", body);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        final ArgumentCaptor<IdentityProviderConfig> captor = ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(publisher).save(captor.capture());
        assertThat(captor.getValue().alias()).isEqualTo("digid");
        assertThat(captor.getValue().enabled()).isFalse();
    }

    @Test
    void delete_returns204_whenRemoved_and404_whenAbsent() {
        when(publisher.delete(new IdentityProviderRef("gov", "digid"))).thenReturn(Boolean.TRUE);
        when(publisher.delete(new IdentityProviderRef("gov", "ghost"))).thenReturn(Boolean.FALSE);

        assertThat(controller.delete("gov", "digid").getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(controller.delete("gov", "ghost").getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void responses_neverCarrySecretValues_onlyKeySetFlags() {
        final IdentityProviderConfig oidc = new IdentityProviderConfig("gov", "up", "oidc", "Up", true,
                Map.of("clientId", "web", "clientSecret", "s3cret"));
        final IdentityProviderConfig eid = new IdentityProviderConfig("gov", "digid", "digid", "DigiD", true,
                Map.of("ssoUrl", "https://idp", "spSigningPrivateKey", "PEM"));
        when(publisher.list("gov")).thenReturn(List.of(oidc, eid));
        when(publisher.get(new IdentityProviderRef("gov", "up"))).thenReturn(oidc);
        when(publisher.save(any(IdentityProviderConfig.class))).thenReturn(oidc);

        final List<IdentityProviderAdminView> list = controller.list("gov");
        assertThat(list.get(0).config()).containsEntry("clientId", "web").containsEntry("clientSecretSet", true)
                .doesNotContainKey("clientSecret");
        assertThat(list.get(1).config()).containsEntry("spSigningPrivateKeySet", true)
                .containsEntry("spDecryptionPrivateKeySet", false).doesNotContainKey("spSigningPrivateKey");
        assertThat(controller.get("gov", "up").getBody().config()).doesNotContainKey("clientSecret");
        assertThat(controller.create("gov", new IdentityProviderRequest("up", "oidc", "Up", true,
                Map.of("clientSecret", "s3cret"))).getBody().config()).doesNotContainKey("clientSecret")
                .containsEntry("clientSecretSet", true);
    }

    @Test
    void aNewSecretTogetherWithItsClearFlag_isRejected_andNothingIsSaved() {
        final IdentityProviderRequest body = new IdentityProviderRequest("up", "oidc", "Up", true,
                Map.of("clientSecret", "new", "clearClientSecret", "true"));

        assertThatThrownBy(() -> controller.update("gov", "up", body))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                        .containsKey("config.clearClientSecret"));
        verify(publisher, never()).save(any(IdentityProviderConfig.class));
    }

    // ------------------------------------------------------------------ EUDI wallet (Task 19): validated writes

    private static final TestPki ACCESS_PKI = TestPki.create("Admin Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestPki PID_ISSUERS = TestPki.create("Admin PID Provider");

    private IdentityProviderAdminController walletController(final DeploymentProfile profile) {
        final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", "gov");
        return new IdentityProviderAdminController(publisher, new WalletConfigValidator(keys, profile));
    }

    private static Map<String, String> walletSettings() {
        final Map<String, String> m = new java.util.HashMap<>();
        m.put("accessKeyRef", "software:gov/eudi-access");
        m.put("trustAnchors", PID_ISSUERS.rootPem());
        return m;
    }

    @Test
    void aWalletConnectionIsValidatedPerField_andAnInvalidOneIsNotSaved() {
        final Map<String, String> settings = walletSettings();
        settings.put("transactionTtlSeconds", "5");
        settings.put("credentialFormats", "not a list");
        settings.put("accessKeyRef", "software:other/eudi-access"); // another realm's key
        final IdentityProviderRequest body = new IdentityProviderRequest("eudi", "openid4vp", "Wallet", true, settings);

        assertThatThrownBy(() -> walletController(DeploymentProfile.production()).create("gov", body))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                        .containsKeys("config.transactionTtlSeconds", "config.credentialFormats",
                                "config.accessKeyRef"));
        verify(publisher, never()).save(any(IdentityProviderConfig.class));
    }

    @Test
    void aValidWalletConnectionIsSaved() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        final IdentityProviderRequest body = new IdentityProviderRequest("eudi", "eudi-wallet", "Wallet", true,
                walletSettings());

        assertThat(walletController(DeploymentProfile.production()).create("gov", body).getStatusCode())
                .isEqualTo(HttpStatus.CREATED);
        verify(publisher).save(any(IdentityProviderConfig.class));
    }

    @Test
    void aWalletUpdateKeepingTheStoredDevKeyIsValidatedWithIt() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        final Map<String, String> stored = walletSettings();
        stored.remove("accessKeyRef");
        stored.put("accessCertificateChain", TestPki.pem(ACCESS.certificate()) + TestPki.pem(ACCESS.chain().get(1)));
        stored.put("accessCertificatePrivateKey", pkcs8(ACCESS.privateKey()));
        when(publisher.get(new IdentityProviderRef("gov", "eudi")))
                .thenReturn(new IdentityProviderConfig("gov", "eudi", "wallet", "Wallet", true, stored));
        final Map<String, String> update = new java.util.HashMap<>(stored);
        update.remove("accessCertificatePrivateKey"); // write-only: absent keeps the stored one

        assertThat(walletController(DeploymentProfile.development()).update("gov", "eudi",
                new IdentityProviderRequest("eudi", "wallet", "Wallet", true, update)).getStatusCode())
                .isEqualTo(HttpStatus.OK);

        update.put("clearAccessCertificatePrivateKey", "true"); // without the key the connection has none
        assertThatThrownBy(() -> walletController(DeploymentProfile.development()).update("gov", "eudi",
                new IdentityProviderRequest("eudi", "wallet", "Wallet", true, update)))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                        .containsKey("config.accessKeyRef"));
    }

    @Test
    void nonWalletConnectionsAreNotRunThroughTheWalletValidator() {
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));

        assertThat(walletController(DeploymentProfile.production()).create("gov",
                new IdentityProviderRequest("digid", "saml", "DigiD", true, Map.of("ssoUrl", "https://idp")))
                .getStatusCode()).isEqualTo(HttpStatus.CREATED);
    }

    private static String pkcs8(final java.security.PrivateKey key) {
        return "-----BEGIN PRIVATE KEY-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(key.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    void withoutTheWalletValidatorAWalletWriteFailsClosed() {
        final IdentityProviderRequest body = new IdentityProviderRequest("eudi", "eudi-wallet", "Wallet", true,
                walletSettings());

        assertThatThrownBy(() -> controller.create("gov", body))
                .isInstanceOf(ProviderValidationException.class)
                .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors()).containsKey("protocol"));
        verify(publisher, never()).save(any(IdentityProviderConfig.class));
    }

    @Test
    void aPaddedOrUpperCaseWalletProtocolIsValidatedToo() {
        final Map<String, String> settings = walletSettings();
        settings.put("transactionTtlSeconds", "5");
        for (final String protocol : List.of(" Wallet ", "OPENID4VP")) {
            assertThatThrownBy(() -> walletController(DeploymentProfile.production()).create("gov",
                    new IdentityProviderRequest("eudi", protocol, "Wallet", true, settings)))
                    .isInstanceOf(ProviderValidationException.class)
                    .satisfies(e -> assertThat(((ProviderValidationException) e).fieldErrors())
                            .containsKey("config.transactionTtlSeconds"));
        }
        verify(publisher, never()).save(any(IdentityProviderConfig.class));
    }

    @Test
    void theProtocolIsStoredNormalised_trimmedAndLowerCase() {
        // Task 19 carry-over: ProviderSecretKeys.keysFor (and every runtime lookup) sees the canonical protocol.
        when(publisher.save(any(IdentityProviderConfig.class))).thenAnswer(inv -> inv.getArgument(0));
        controller.create("gov", new IdentityProviderRequest("up", "  OIDC ", "Upstream", true, Map.of("clientId", "c")));
        controller.update("gov", "up", new IdentityProviderRequest("up", "Oidc\t", "Upstream", true, Map.of()));

        final ArgumentCaptor<IdentityProviderConfig> captor = ArgumentCaptor.forClass(IdentityProviderConfig.class);
        verify(publisher, org.mockito.Mockito.times(2)).save(captor.capture());
        assertThat(captor.getAllValues()).extracting(IdentityProviderConfig::protocol).containsOnly("oidc");
    }
}
