/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.testwallet.DcApiWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link AuthorizationRequestFactory#dcApiRequest}: the request handed to {@code navigator.credentials.get} for OpenID4VP
 * over the Digital Credentials API (OpenID4VP 1.0 Appendix A, HAIP 1.0 §5.2), checked the way a wallet does it
 * ({@link DcApiWalletClient}, independent of production code).
 */
class AuthorizationRequestFactoryDcApiTest {

    private static final Instant NOW = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    private static final String HOST = "verifier.example.eu";
    private static final String ORIGIN = "https://verifier.example.eu";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final String HELIX_STATE = "helix-state-must-never-reach-the-wallet";

    private static final TestPki PKI = TestPki.create("Verifier CA");
    private static final TestPki.Leaf LEAF = PKI.issueLeaf(TestPki.LeafSpec.defaults()
            .withSubject("CN=Helix Verifier,O=HelixIAM Test").withDnsNames(HOST));

    private final AuthorizationRequestFactory factory = new AuthorizationRequestFactory(Clock.fixed(NOW, ZoneOffset.UTC));
    private final ECKey encKey = encKey();
    private final SigningKeyHandle key = handle(LEAF);

    private static ECKey encKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("enc-1").keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SigningKeyHandle handle(final TestPki.Leaf leaf) {
        final JWSSigner signer;
        try {
            signer = new ECDSASigner((ECPrivateKey) leaf.privateKey());
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
        return new SigningKeyHandle() {
            @Override
            public String keyRef() {
                return "software:acme/verifier";
            }

            @Override
            public JWSAlgorithm algorithm() {
                return JWSAlgorithm.ES256;
            }

            @Override
            public List<X509Certificate> certificateChain() {
                return leaf.chain();
            }

            @Override
            public JWSSigner signer() {
                return signer;
            }
        };
    }

    private static WalletProviderConfig config(final Map<String, String> settings) {
        return WalletProviderConfig.fromStored("eudi", "EUDI Wallet", settings);
    }

    private WalletTransaction tx(final WalletTransaction.Status status) {
        final WalletProviderConfig cfg = config(Map.of());
        final String dcql = new DcqlQueryBuilder().pidQuery(cfg.pid().toQuerySpec(), cfg.credentialFormats())
                .toString();
        return new WalletTransaction("tx-1", "same-1", "cross-1", "resp-1", "acme", "eudi", HELIX_STATE, "binding",
                NONCE, encKey.toJSONString(), dcql, null, status, null, null, null, NOW.minusSeconds(5),
                NOW.plusSeconds(300));
    }

    private DcApiWalletClient.DcApiRequest asWallet(final AuthorizationRequestFactory.DcApiRequest request,
                                                    final String origin) {
        return DcApiWalletClient.verify(request.protocol(), request.data(), origin, NOW);
    }

    @Test
    void signedRequest_isAnX509HashJwsWithExpectedOrigins_andNoResponseUriOrState() throws Exception {
        final AuthorizationRequestFactory.DcApiRequest request = factory.dcApiRequest(
                tx(WalletTransaction.Status.CREATED), config(Map.of("dcApi.enabled", "true")), key,
                List.of(ORIGIN, "https://id.example.eu"));

        assertThat(request.protocol()).isEqualTo("openid4vp-v1-signed");
        assertThat(request.data()).containsOnlyKeys("request");
        final DcApiWalletClient.DcApiRequest seen = asWallet(request, ORIGIN);
        assertThat(seen.clientId()).isEqualTo(AuthorizationRequestFactory.clientId(config(Map.of()), key));
        assertThat(seen.claims()).containsEntry("response_mode", "dc_api.jwt").containsEntry("nonce", NONCE)
                .containsEntry("expected_origins", List.of(ORIGIN, "https://id.example.eu"))
                .doesNotContainKeys("response_uri", "redirect_uri", "state", "wallet_nonce");
        assertThat(seen.encryptionKey().toPublicJWK()).isEqualTo(encKey.toPublicJWK());
        assertThat(seen.encValues()).containsExactly("A128GCM", "A256GCM");
        final SignedJWT jwt = SignedJWT.parse((String) request.data().get("request"));
        assertThat(jwt.getHeader().getType().getType()).isEqualTo("oauth-authz-req+jwt");
        assertThat(jwt.getHeader().getX509CertChain()).hasSize(LEAF.chain().size());
        assertThat(jwt.serialize()).doesNotContain(HELIX_STATE);
        assertThat(jwt.getJWTClaimsSet().getExpirationTime().toInstant()).isEqualTo(NOW.plusSeconds(300));
    }

    @Test
    void signedRequest_isRefusedByTheWallet_atAnotherOrigin() {
        final AuthorizationRequestFactory.DcApiRequest request = factory.dcApiRequest(
                tx(WalletTransaction.Status.CREATED), config(Map.of("dcApi.enabled", "true")), key, List.of(ORIGIN));

        assertThatThrownBy(() -> asWallet(request, "https://evil.example.com"))
                .hasMessageContaining("expected_origins");
    }

    @Test
    void unsignedRequest_carriesTheParametersInDataWithoutClientId() {
        final AuthorizationRequestFactory.DcApiRequest request = factory.dcApiRequest(
                tx(WalletTransaction.Status.CREATED),
                config(Map.of("dcApi.enabled", "true", "dcApi.request", "unsigned")), key, List.of(ORIGIN));

        assertThat(request.protocol()).isEqualTo("openid4vp-v1-unsigned");
        assertThat(request.data()).containsKeys("response_type", "response_mode", "nonce", "client_metadata",
                "dcql_query").doesNotContainKeys("client_id", "expected_origins", "request", "state", "response_uri");
        final DcApiWalletClient.DcApiRequest seen = asWallet(request, "https://any.example");
        assertThat(seen.clientId()).isNull();
        assertThat(seen.responseMode()).isEqualTo("dc_api.jwt");
    }

    @Test
    void devDirectPost_becomesUnencryptedDcApi_withoutAKey() {
        final AuthorizationRequestFactory.DcApiRequest request = factory.dcApiRequest(
                tx(WalletTransaction.Status.CREATED),
                config(Map.of("dcApi.enabled", "true", "responseMode", "direct_post")), key, List.of(ORIGIN));

        final DcApiWalletClient.DcApiRequest seen = asWallet(request, ORIGIN);
        assertThat(seen.responseMode()).isEqualTo("dc_api");
        assertThat(seen.encryptionKey()).isNull();
        assertThat(seen.claims().get("client_metadata")).isInstanceOf(Map.class);
    }

    @Test
    void sanDnsClientId_doesNotNeedAResponseUriHost() {
        final AuthorizationRequestFactory.DcApiRequest request = factory.dcApiRequest(
                tx(WalletTransaction.Status.CREATED), config(Map.of("dcApi.enabled", "true",
                        "clientIdScheme", "x509_san_dns", "clientIdHost", HOST)), key, List.of("https://other.example"));

        assertThat(asWallet(request, "https://other.example").clientId()).isEqualTo("x509_san_dns:" + HOST);
    }

    @Test
    void refused_withoutOrigins_forAnExpiredTransaction_orWhenTheDcApiIsOff() {
        final WalletProviderConfig on = config(Map.of("dcApi.enabled", "true"));
        assertThatThrownBy(() -> factory.dcApiRequest(tx(WalletTransaction.Status.CREATED), on, key, List.of()))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> factory.dcApiRequest(tx(WalletTransaction.Status.CREATED), config(Map.of()), key,
                List.of(ORIGIN))).isInstanceOf(IllegalStateException.class);
        final WalletTransaction expired = new WalletTransaction("tx-1", "s", "c", "r", "acme", "eudi", HELIX_STATE,
                "binding", NONCE, encKey.toJSONString(), "{}", null, WalletTransaction.Status.CREATED, null, null,
                null, NOW.minusSeconds(400), NOW.minusSeconds(1));
        assertThatThrownBy(() -> factory.dcApiRequest(expired, on, key, List.of(ORIGIN)))
                .isInstanceOf(IllegalStateException.class);
    }
}
