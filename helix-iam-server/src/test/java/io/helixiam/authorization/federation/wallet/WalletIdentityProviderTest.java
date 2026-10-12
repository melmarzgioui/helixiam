/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64URL;
import io.helixiam.authorization.federation.PresentedProvider;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.spi.IdpMetadata;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Task 19: the EUDI wallet on the federation SPI. {@code start} persists a CREATED transaction and sends the browser to
 * the wallet page; {@code callback} redeems the response code for the verified identity only with the login's state
 * and this browser's binding; the provider is built from a validated config with one signing key handle.
 */
class WalletIdentityProviderTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String KEY_REF = "software:acme/eudi-access";
    private static final String HOST = "verifier.example.eu";
    private static final String STATE = "helix-state-1";

    private static final TestPki PKI = TestPki.create("Wallet Access");
    private static final TestPki.Leaf ACCESS = PKI.issueLeaf(TestPki.LeafSpec.defaults()
            .withSubject("CN=Helix Verifier").withDnsNames(HOST));
    private static final TestPki.Leaf NO_SAN = PKI.issueLeaf(TestPki.LeafSpec.defaults()
            .withSubject("CN=Helix Verifier without SAN"));
    private static final TestPki ISSUERS = TestPki.create("Wallet PID Provider");

    private final WalletTransactionStore store = new InMemoryWalletTransactionStore();
    private final FakeKeys keys = new FakeKeys(ACCESS);

    private WalletIdentityProviders providers(final RealmSigningKeys signingKeys, final DeploymentProfile profile) {
        return new WalletIdentityProviders(new WalletConfigValidator(signingKeys, profile), signingKeys, store,
                new OutboundUrlGuard(), mock(AuditLog.class));
    }

    private static Map<String, String> valid() {
        final Map<String, String> m = new HashMap<>();
        m.put("accessKeyRef", KEY_REF);
        m.put("trustAnchors", ISSUERS.rootPem());
        return m;
    }

    private static WalletProviderConfig config(final Map<String, String> stored) {
        return WalletProviderConfig.fromStored(ALIAS, "EU Digital Identity Wallet", stored);
    }

    private WalletIdentityProvider provider() {
        return providers(keys, DeploymentProfile.production()).build(REALM, config(valid()));
    }

    /** A browser binding hash as the broker makes one: base64url SHA-256 (here of a seed). */
    private static String binding(final String seed) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    java.security.MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.US_ASCII)));
        } catch (final java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static IdentityProvider.AuthnRequestContext startContext(final String bindingHash) {
        return new IdentityProvider.AuthnRequestContext(REALM, STATE,
                "https://helix.example/realms/acme/broker/eudi-wallet/callback", bindingHash);
    }

    private static IdentityProvider.CallbackContext callbackContext(final Map<String, String> params,
            final String expectedState, final String bindingHash) {
        return new IdentityProvider.CallbackContext(REALM, params, expectedState, null,
                "https://helix.example/realms/acme/broker/eudi-wallet/callback", null, bindingHash);
    }

    private static String txId(final IdentityProvider.RedirectResponse redirect) {
        return redirect.location().substring(redirect.location().indexOf("?tx=") + 4);
    }

    /** Runs the wallet half of a same-device login (Task 18's endpoints) and returns the response code. */
    private String verifiedCode(final String transactionId, final BrokeredIdentity identity) {
        final WalletTransaction tx = store.byTransactionId(transactionId).orElseThrow();
        assertThat(store.claimRequest(tx.sameDeviceRequestId())).isPresent();
        assertThat(store.claimResponse(tx.responseId())).isPresent();
        final String code = "code-" + transactionId;
        assertThat(store.complete(transactionId, code, VerifiedIdentityJson.write(identity))).isTrue();
        return code;
    }

    private static BrokeredIdentity identity() {
        return new BrokeredIdentity(ALIAS, "DE/PAN-0001", null, false, Map.of("given_name", "Erika"),
                "http://eidas.europa.eu/LoA/high");
    }

    private static void assertRefused(final Runnable call, final WalletErrorCode code) {
        assertThatThrownBy(call::run).isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    // ------------------------------------------------------------------------------------------------ metadata

    @Test
    void metadataIsTheWalletProtocolWithTheNeutralWalletIcon() {
        final IdpMetadata metadata = provider().metadata();

        assertThat(metadata.alias()).isEqualTo(ALIAS);
        assertThat(metadata.protocol()).isEqualTo(IdpMetadata.Protocol.WALLET);
        assertThat(metadata.displayName()).isEqualTo("EU Digital Identity Wallet");
        assertThat(metadata.iconKey()).isEqualTo("eudi-wallet");
    }

    // ------------------------------------------------------------------------------------------------ start

    @Test
    void startPersistsACreatedTransactionAndRedirectsToTheWalletPage() throws Exception {
        final WalletIdentityProvider provider = provider();
        final String bindingHash = binding("browser");

        final IdentityProvider.RedirectResponse redirect = provider.start(startContext(bindingHash));

        assertThat(redirect.binding()).isEqualTo(IdentityProvider.Binding.REDIRECT);
        // context-relative (Task 18): the broker's "redirect:" resolves it under /realms/acme
        assertThat(redirect.location()).startsWith("/broker/eudi-wallet/wallet?tx=");
        final WalletTransaction tx = store.byTransactionId(txId(redirect)).orElseThrow();
        assertThat(tx.status()).isEqualTo(WalletTransaction.Status.CREATED);
        assertThat(tx.realmId()).isEqualTo(REALM);
        assertThat(tx.providerAlias()).isEqualTo(ALIAS);
        assertThat(tx.helixState()).isEqualTo(STATE);
        assertThat(tx.browserBindingHash()).isEqualTo(bindingHash);
        assertThat(Base64.getUrlDecoder().decode(tx.nonce())).hasSize(16);
        assertThat(new HashSet<>(List.of(tx.transactionId(), tx.sameDeviceRequestId(), tx.crossDeviceRequestId(),
                tx.responseId(), tx.nonce()))).hasSize(5);
        for (final String id : List.of(tx.transactionId(), tx.sameDeviceRequestId(), tx.crossDeviceRequestId(),
                tx.responseId())) {
            assertThat(Base64.getUrlDecoder().decode(id).length).isGreaterThanOrEqualTo(16);
        }
        final ECKey enc = ECKey.parse(tx.encryptionJwkJson());
        assertThat(enc.getCurve()).isEqualTo(Curve.P_256);
        assertThat(enc.isPrivate()).isTrue();
        assertThat(enc.getKeyID()).isNotBlank();
        assertThat(enc.getKeyUse()).isEqualTo(KeyUse.ENCRYPTION);
        final JsonNode dcql = StrictJson.MAPPER.readTree(tx.dcqlQueryJson());
        assertThat(dcql).isEqualTo(new DcqlQueryBuilder().pidQuery(provider.config().pid().toQuerySpec(),
                provider.config().credentialFormats()));
        assertThat(Duration.between(tx.createdAt(), tx.expiresAt()))
                .isEqualTo(Duration.ofSeconds(WalletProviderConfig.DEFAULT_TRANSACTION_TTL_SECONDS));
    }

    @Test
    void eachStartIsANewTransactionWithItsOwnSecrets() throws Exception {
        final WalletIdentityProvider provider = provider();

        final WalletTransaction a = store.byTransactionId(txId(provider.start(startContext(binding("a"))))).orElseThrow();
        final WalletTransaction b = store.byTransactionId(txId(provider.start(startContext(binding("a"))))).orElseThrow();

        assertThat(b.transactionId()).isNotEqualTo(a.transactionId());
        assertThat(b.nonce()).isNotEqualTo(a.nonce());
        assertThat(ECKey.parse(b.encryptionJwkJson()).getKeyID()).isNotEqualTo(ECKey.parse(a.encryptionJwkJson()).getKeyID());
    }

    @Test
    void startWithoutABrowserBindingIsRefused() {
        assertThatThrownBy(() -> provider().start(new IdentityProvider.AuthnRequestContext(REALM, STATE, "cb")))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aStoredProviderStartedFromAnotherRealmIsRefused() {
        final WalletIdentityProvider provider = provider(); // stored in REALM

        assertThat(provider.keyRealm()).isEqualTo(REALM);
        assertThatThrownBy(() -> provider.start(new IdentityProvider.AuthnRequestContext("other-realm", STATE,
                "https://helix.example/realms/other-realm/broker/eudi-wallet/callback", binding("b"))))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aYamlProviderStartsFromAnyRealmWithItsMasterKey() {
        final TestAccessKeys masterKeys = new TestAccessKeys(ACCESS, "eudi-access", "master");
        final Map<String, String> stored = valid();
        stored.put("accessKeyRef", masterKeys.ref("master"));
        final WalletIdentityProvider provider = providers(masterKeys, DeploymentProfile.production())
                .buildFromYaml(config(stored));

        assertThat(provider.keyRealm()).isNull();
        for (final String realm : List.of("acme", "gov", "master")) {
            final IdentityProvider.RedirectResponse redirect = provider.start(new IdentityProvider.AuthnRequestContext(
                    realm, STATE, "https://helix.example/cb", binding(realm)));
            assertThat(store.byTransactionId(txId(redirect)).orElseThrow().realmId()).isEqualTo(realm);
        }
    }

    // ------------------------------------------------------------------------------------------------ callback

    @Test
    void callbackWithTheRightStateAndBindingReturnsTheVerifiedIdentity() {
        final WalletIdentityProvider provider = provider();
        final String bindingHash = binding("browser");
        final String code = verifiedCode(txId(provider.start(startContext(bindingHash))), identity());

        final BrokeredIdentity result = provider.callback(callbackContext(Map.of("response_code", code), STATE,
                bindingHash));

        assertThat(result).isEqualTo(identity());
    }

    @Test
    void callbackWithAWrongStateIsRefusedAndDoesNotBurnTheCode() {
        final WalletIdentityProvider provider = provider();
        final String bindingHash = binding("browser");
        final String code = verifiedCode(txId(provider.start(startContext(bindingHash))), identity());

        assertRefused(() -> provider.callback(callbackContext(Map.of("response_code", code), "other-state",
                bindingHash)), WalletErrorCode.REPLAY);

        assertThat(provider.callback(callbackContext(Map.of("response_code", code), STATE, bindingHash)))
                .isEqualTo(identity());
    }

    @Test
    void callbackFromAnotherBrowserIsRefused() {
        final WalletIdentityProvider provider = provider();
        final String code = verifiedCode(txId(provider.start(startContext(binding("victim")))), identity());

        assertRefused(() -> provider.callback(callbackContext(Map.of("response_code", code), STATE,
                binding("attacker"))), WalletErrorCode.REPLAY);
    }

    @Test
    void aReusedResponseCodeIsRefused() {
        final WalletIdentityProvider provider = provider();
        final String bindingHash = binding("browser");
        final String code = verifiedCode(txId(provider.start(startContext(bindingHash))), identity());
        provider.callback(callbackContext(Map.of("response_code", code), STATE, bindingHash));

        assertRefused(() -> provider.callback(callbackContext(Map.of("response_code", code), STATE, bindingHash)),
                WalletErrorCode.REPLAY);
    }

    @Test
    void anUnknownResponseCodeIsRefused() {
        assertRefused(() -> provider().callback(callbackContext(Map.of("response_code", "made-up"), STATE,
                binding("browser"))), WalletErrorCode.REPLAY);
    }

    @Test
    void aCallbackWithoutCodeStateOrBindingIsRefused() {
        final WalletIdentityProvider provider = provider();
        assertRefused(() -> provider.callback(callbackContext(Map.of(), STATE, binding("b"))),
                WalletErrorCode.INVALID_RESPONSE);
        assertRefused(() -> provider.callback(callbackContext(Map.of("response_code", " "), STATE, binding("b"))),
                WalletErrorCode.INVALID_RESPONSE);
        assertRefused(() -> provider.callback(callbackContext(Map.of("response_code", "c"), null, binding("b"))),
                WalletErrorCode.STATE_MISMATCH);
        assertRefused(() -> provider.callback(callbackContext(Map.of("response_code", "c"), STATE, null)),
                WalletErrorCode.BROWSER_MISMATCH);
    }

    @Test
    void aCodeFromAnotherProvidersTransactionIsRefused() {
        final Map<String, String> otherStored = valid();
        final WalletIdentityProvider other = providers(keys, DeploymentProfile.production())
                .build(REALM, WalletProviderConfig.fromStored("other-wallet", "Other", otherStored));
        final String bindingHash = binding("browser");
        final String code = verifiedCode(txId(other.start(startContext(bindingHash))), identity());

        assertRefused(() -> provider().callback(callbackContext(Map.of("response_code", code), STATE, bindingHash)),
                WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void logoutIsANoOp() {
        provider().logout(new IdentityProvider.LogoutContext(REALM, "user-1"));
    }

    // ------------------------------------------------------------------------------------------------ Task 18 view

    @Test
    void exposesOneStatusPolicyInstanceToItsStatusClientAndItsVerificationContext() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = store.byTransactionId(txId(provider.start(startContext(binding("b")))))
                .orElseThrow();

        final VerificationContext ctx = provider.verificationContext(tx, "https://helix.example/response", null);

        assertThat(ctx.statusPolicy()).isSameAs(provider.statusPolicy());
        assertThat(provider.statusClient().policy()).isSameAs(provider.statusPolicy());
        assertThat(ctx.anchors()).isSameAs(provider.trustAnchors());
        assertThat(ctx.nonce()).isEqualTo(tx.nonce());
        assertThat(ctx.clientId()).isEqualTo(AuthorizationRequestFactory.clientId(provider.config(),
                provider.signingKey()));
        assertThat(ctx.acceptedVcts()).isEqualTo(provider.config().pid().acceptedVcts());
        assertThat(ctx.acceptedDoctype()).isEqualTo(provider.config().pid().acceptedDoctype());
        assertThat(ctx.clockSkew()).isEqualTo(Duration.ofSeconds(provider.config().clockSkewSeconds()));
        assertThat(provider.verifiers().keySet()).containsExactlyInAnyOrderElementsOf(
                provider.config().credentialFormats());
        assertThat(provider.transactions()).isSameAs(store);
    }

    @Test
    void verifiersAreBuiltForTheConfiguredFormatsOnly() {
        final Map<String, String> stored = valid();
        stored.put("credentialFormats", "[\"mso_mdoc\"]");
        final WalletIdentityProvider provider = providers(keys, DeploymentProfile.production())
                .build(REALM, config(stored));

        assertThat(provider.verifiers()).containsOnlyKeys(DcqlQueryBuilder.MDOC_FORMAT);
    }

    @Test
    void theProviderIsFoundBehindItsPresentationWrapper() {
        final WalletIdentityProvider provider = provider();

        assertThat(WalletIdentityProvider.from(new PresentedProvider(provider, "eudi-wallet", null))).containsSame(provider);
        assertThat(WalletIdentityProvider.from(provider)).containsSame(provider);
        assertThat(WalletIdentityProvider.from(mock(IdentityProvider.class))).isEmpty();
    }

    // ------------------------------------------------------------------------------------------------ build

    @Test
    void anInvalidConfigIsRefusedAtBuild() {
        final Map<String, String> stored = valid();
        stored.put("transactionTtlSeconds", "5");

        assertThatThrownBy(() -> providers(keys, DeploymentProfile.production()).build(REALM, config(stored)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("transactionTtlSeconds");
    }

    @Test
    void sanDnsWithAKeyWhoseLeafLacksTheSanIsRefusedAtBuild() {
        final Map<String, String> stored = valid();
        stored.put("clientIdScheme", "x509_san_dns");
        stored.put("clientIdHost", HOST);

        assertThatThrownBy(() -> providers(new FakeKeys(NO_SAN), DeploymentProfile.production())
                .build(REALM, config(stored)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("clientIdHost");
    }

    @Test
    void sanDnsIsCheckedOnTheSameHandleThatSigns() {
        final Map<String, String> stored = valid();
        stored.put("clientIdScheme", "x509_san_dns");
        stored.put("clientIdHost", HOST);

        // A key store answering differently per resolve: the handle that signs is the one validated.
        final FakeKeys badThenGood = new FakeKeys(NO_SAN, ACCESS);
        assertThatThrownBy(() -> providers(badThenGood, DeploymentProfile.production()).build(REALM, config(stored)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("clientIdHost");

        final FakeKeys goodThenBad = new FakeKeys(ACCESS, NO_SAN);
        final WalletIdentityProvider provider = providers(goodThenBad, DeploymentProfile.production())
                .build(REALM, config(stored));
        assertThat(provider.signingKey().certificateChain()).isEqualTo(ACCESS.chain());
        assertThat(goodThenBad.resolves.get()).isEqualTo(1);
    }

    @Test
    void anUnresolvableKeyRefIsRefusedAtBuild() {
        final Map<String, String> stored = valid();
        stored.put("accessKeyRef", "software:acme/missing");

        assertThatThrownBy(() -> providers(keys, DeploymentProfile.production()).build(REALM, config(stored)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("accessKeyRef");
    }

    @Test
    void theDevPemKeyBecomesARestrictedHandleOverTheConfiguredChain() throws Exception {
        final Map<String, String> stored = valid();
        stored.remove("accessKeyRef");
        stored.put("accessCertificateChain", TestPki.pem(ACCESS.certificate()) + TestPki.pem(ACCESS.chain().get(1)));
        stored.put("accessCertificatePrivateKey", WalletConfigValidatorTest.pkcs8Pem(ACCESS.privateKey()));

        final WalletIdentityProvider provider = providers(keys, DeploymentProfile.development())
                .build(REALM, config(stored));

        final SigningKeyHandle handle = provider.signingKey();
        assertThat(handle.certificateChain()).isEqualTo(ACCESS.chain());
        assertThat(handle.algorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(handle.signer()).isNotInstanceOf(ECDSASigner.class);
        assertThat(handle.toString()).doesNotContain("PRIVATE");
        final byte[] input = "probe".getBytes(StandardCharsets.US_ASCII);
        final Base64URL signature = handle.signer().sign(new JWSHeader(JWSAlgorithm.ES256), input);
        assertThat(new ECDSAVerifier((ECPublicKey) ACCESS.certificate().getPublicKey())
                .verify(new JWSHeader(JWSAlgorithm.ES256), input, signature)).isTrue();
        assertThatThrownBy(() -> handle.signer().sign(new JWSHeader(JWSAlgorithm.ES384), input))
                .isInstanceOf(JOSEException.class);
        assertThat(keys.resolves.get()).as("the dev path never touches the key store").isZero();
    }

    @Test
    void theDevPemKeyIsRefusedOutsideDev() {
        final Map<String, String> stored = valid();
        stored.remove("accessKeyRef");
        stored.put("accessCertificateChain", TestPki.pem(ACCESS.certificate()) + TestPki.pem(ACCESS.chain().get(1)));
        stored.put("accessCertificatePrivateKey", WalletConfigValidatorTest.pkcs8Pem(ACCESS.privateKey()));

        assertThatThrownBy(() -> providers(keys, DeploymentProfile.production()).build(REALM, config(stored)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("accessCertificatePrivateKey")
                .hasMessageNotContaining("PRIVATE KEY");
    }

    /** Resolves {@link #KEY_REF} in {@link #REALM} to the given leaves in turn (the last one repeats). */
    private static final class FakeKeys implements RealmSigningKeys {
        private final Deque<TestPki.Leaf> leaves;
        private final AtomicInteger resolves = new AtomicInteger();

        FakeKeys(final TestPki.Leaf... leaves) {
            this.leaves = new ArrayDeque<>(List.of(leaves));
        }

        @Override
        public SigningKeyHandle resolve(final String realmId, final String keyRef) {
            resolves.incrementAndGet();
            if (!REALM.equals(realmId) || !KEY_REF.equals(keyRef)) {
                throw new NoSuchElementException("Signing key not found in this realm");
            }
            final TestPki.Leaf leaf = leaves.size() > 1 ? leaves.poll() : leaves.peek();
            final JWSSigner signer;
            try {
                signer = new ECDSASigner((ECPrivateKey) leaf.privateKey());
            } catch (final JOSEException e) {
                throw new IllegalStateException(e);
            }
            final List<X509Certificate> chain = leaf.chain();
            return new SigningKeyHandle() {
                @Override
                public String keyRef() {
                    return KEY_REF;
                }

                @Override
                public JWSAlgorithm algorithm() {
                    return JWSAlgorithm.ES256;
                }

                @Override
                public List<X509Certificate> certificateChain() {
                    return chain;
                }

                @Override
                public JWSSigner signer() {
                    return signer;
                }
            };
        }

        @Override
        public String importKey(final String realmId, final String name, final String privateKeyPem,
                                final String certificateChainPem) {
            throw new UnsupportedOperationException();
        }
    }
}
