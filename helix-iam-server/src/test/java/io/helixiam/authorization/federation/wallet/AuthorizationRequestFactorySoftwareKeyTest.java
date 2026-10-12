/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The request object signed through the production key store: a key imported into {@code SoftwareRealmSigningKeys}
 * (Task 5's import path, shared e2e context) resolves to a handle whose {@code RestrictedSigner} signs; the wallet
 * side ({@link Oid4vpWalletClient}) then verifies the JWS (JOSE r||s ECDSA) with the x5c leaf and the
 * {@code x509_hash} binding.
 */
class AuthorizationRequestFactorySoftwareKeyTest extends AbstractE2eTest {

    @Test
    void requestObjectSignedThroughARealSoftwareKeyHandle_verifiesInTheWallet() throws Exception {
        final String realm = E2eSeed.unique("wallet-req");
        final TestPki.Leaf leaf = TestPki.create("Verifier CA").issueLeaf(TestPki.LeafSpec.defaults()
                .withSubject("CN=Helix Verifier,O=HelixIAM Test").withDnsNames("verifier.example.eu"));
        final RealmSigningKeys keys = context.getBean(RealmSigningKeys.class);
        final SigningKeyHandle handle = keys.resolve(realm, keys.importKey(realm, "eudi-access", pkcs8(leaf),
                TestPki.pem(leaf.chain().get(0)) + TestPki.pem(leaf.chain().get(1))));
        assertThat(handle.signer()).isNotInstanceOf(ECDSASigner.class); // the RestrictedSigner path

        final Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        final WalletProviderConfig cfg = WalletProviderConfig.fromStored("eudi", "EUDI Wallet", Map.of());
        final ECKey encKey = new ECKeyGenerator(Curve.P_256).keyID("k1").keyUse(KeyUse.ENCRYPTION)
                .algorithm(JWEAlgorithm.ECDH_ES).generate();
        final WalletTransaction tx = new WalletTransaction("tx-soft", "same-id", "cross-id", "resp-id", realm, "eudi",
                "helix-state", "binding", "nonce-1", encKey.toJSONString(),
                new DcqlQueryBuilder().pidQuery(cfg.pid().toQuerySpec(), cfg.credentialFormats()).toString(), null,
                WalletTransaction.Status.CREATED, null, null, null, now, now.plusSeconds(300));
        final AuthorizationRequestFactory factory = new AuthorizationRequestFactory(Clock.fixed(now, ZoneOffset.UTC));
        final String base = "https://verifier.example.eu";

        final String jwt = factory.signedRequestObject(tx, cfg, handle, base);
        final Oid4vpWalletClient.VerifiedRequest verified = Oid4vpWalletClient.fetchAndVerifyRequest(
                factory.invocationUrl(tx, cfg, handle, Flow.CROSS_DEVICE, base), uri -> jwt, now);

        assertThat(SignedJWT.parse(jwt).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        assertThat(verified.clientId()).isEqualTo(AuthorizationRequestFactory.clientId(cfg, handle));
        assertThat(verified.state()).isEqualTo(AuthorizationRequestFactory.walletState("tx-soft"));
    }

    private static String pkcs8(final TestPki.Leaf leaf) throws Exception {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(new JcaPKCS8Generator(leaf.privateKey(), null));
        }
        return out.toString();
    }
}
