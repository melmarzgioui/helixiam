/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.federation.wallet.dcql.DcqlQueryBuilder;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.VerifiedRequest;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction.Flow;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link AuthorizationRequestFactory}: the signed request object (OpenID4VP 1.0 §5, HAIP §5), the {@code client_id}
 * and the wallet invocation URL, verified the way a wallet does it ({@link TestWallet#fetchAndVerifyRequest}), with
 * expected values (digests, encodings) computed independently of production code.
 */
class AuthorizationRequestFactoryTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    private static final Instant EXPIRES = NOW.plusSeconds(300);
    private static final String BASE = "https://verifier.example.eu";
    private static final String HOST = "verifier.example.eu";
    private static final String TX_ID = "tx-Qm9vX2lkZW50aWZpZXI";
    private static final String HELIX_STATE = "helix-state-must-never-reach-the-wallet";
    private static final String NONCE = "n-0S6_WzA2Mj";
    private static final String KID = "enc-kid-1";

    private static final TestPki PKI = TestPki.create("Verifier CA");
    private static final TestPki.Leaf LEAF = PKI.issueLeaf(TestPki.LeafSpec.defaults()
            .withSubject("CN=Helix Verifier,O=HelixIAM Test").withDnsNames(HOST));

    private final AuthorizationRequestFactory factory =
            new AuthorizationRequestFactory(Clock.fixed(NOW, ZoneOffset.UTC));
    private final TestWallet wallet = TestWallet.create();
    private final ECKey encKey = encKey();
    private final SigningKeyHandle key = handle(LEAF, JWSAlgorithm.ES256);

    // ------------------------------------------------------------------------------------------------ fixtures

    private static ECKey encKey() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(KID).keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SigningKeyHandle handle(final TestPki.Leaf leaf, final JWSAlgorithm alg) {
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
                return alg;
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

    private static WalletProviderConfig hashConfig() {
        return config(Map.of());
    }

    private static WalletProviderConfig sanConfig() {
        return config(Map.of("clientIdScheme", "x509_san_dns", "clientIdHost", HOST));
    }

    private static String dcql() {
        final WalletProviderConfig cfg = hashConfig();
        return new DcqlQueryBuilder().pidQuery(cfg.pid().toQuerySpec(), cfg.credentialFormats()).toString();
    }

    private WalletTransaction tx(final String sameDeviceId, final String crossDeviceId, final String encJwk) {
        return new WalletTransaction(TX_ID, sameDeviceId, crossDeviceId, "resp-R2VuZXJhdGVk", "acme", "eudi",
                HELIX_STATE, "binding-hash", NONCE, encJwk, dcql(), null, WalletTransaction.Status.CREATED, null,
                null, null, NOW.minusSeconds(5), EXPIRES);
    }

    private WalletTransaction tx() {
        return tx("same-U2FtZURldmljZQ", "cross-Q3Jvc3NEZXZpY2U", encKey.toJSONString());
    }

    private static String expectedHash(final X509Certificate leaf) throws Exception {
        final byte[] digest = MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded());
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static JsonNode payload(final String jwt) throws Exception {
        return JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    /** A wallet run: invocation URL → fetch (answered with the factory's request object) → verify. */
    private VerifiedRequest walletRun(final WalletTransaction tx, final WalletProviderConfig cfg, final Flow flow) {
        final String jwt = factory.signedRequestObject(tx, cfg, key, BASE);
        final String url = factory.invocationUrl(tx, cfg, key, flow, BASE);
        final Function<String, String> fetch = requestUri -> {
            assertThat(requestUri).isEqualTo(AuthorizationRequestFactory.requestUri(BASE, tx, flow));
            return jwt;
        };
        return wallet.fetchAndVerifyRequest(url, fetch, NOW);
    }

    // ------------------------------------------------------------------------------------------------ client_id

    @Test
    void x509HashClientId_isTheUnpaddedBase64urlSha256OfTheLeafDer() throws Exception {
        final String clientId = AuthorizationRequestFactory.clientId(hashConfig(), key);

        assertThat(clientId).isEqualTo("x509_hash:" + expectedHash(LEAF.certificate()));
        assertThat(clientId.substring("x509_hash:".length())).hasSize(43).doesNotContain("=", "+", "/");
    }

    @Test
    void x509HashClientId_isOfTheLeafNotTheIntermediate() throws Exception {
        assertThat(AuthorizationRequestFactory.clientId(hashConfig(), key))
                .isNotEqualTo("x509_hash:" + expectedHash(PKI.intermediate()));
    }

    @Test
    void x509SanDnsClientId_isThePrefixedHost() {
        assertThat(AuthorizationRequestFactory.clientId(sanConfig(), key)).isEqualTo("x509_san_dns:" + HOST);
    }

    // ------------------------------------------------------------------------------------------------ JWS

    @Test
    void walletVerifiesTheRequestWithTheX5cLeaf_andTheX509HashBinding() throws Exception {
        final VerifiedRequest request = walletRun(tx(), hashConfig(), Flow.SAME_DEVICE);

        assertThat(request.clientId()).isEqualTo("x509_hash:" + expectedHash(LEAF.certificate()));
        assertThat(request.claims().get("client_id")).isEqualTo(request.clientId());
    }

    @Test
    void walletVerifiesTheX509SanDnsBinding() {
        final VerifiedRequest request = walletRun(tx(), sanConfig(), Flow.CROSS_DEVICE);

        assertThat(request.clientId()).isEqualTo("x509_san_dns:" + HOST);
    }

    @Test
    void header_hasTypAlgAndALeafFirstStandardBase64X5cWithoutTheRoot() throws Exception {
        final JWSHeader header = SignedJWT.parse(factory.signedRequestObject(tx(), hashConfig(), key, BASE))
                .getHeader();

        assertThat(header.getType()).isEqualTo(new JOSEObjectType("oauth-authz-req+jwt"));
        assertThat(header.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
        final Base64.Encoder std = Base64.getEncoder();
        assertThat(header.getX509CertChain()).extracting(Object::toString).containsExactly(
                std.encodeToString(LEAF.certificate().getEncoded()),
                std.encodeToString(PKI.intermediate().getEncoded()));
        assertThat(header.getX509CertChain()).extracting(Object::toString)
                .doesNotContain(std.encodeToString(PKI.root().getEncoded()));
        assertThat(header.getJWK()).isNull();
    }

    @Test
    void algComesFromTheKey() throws Exception {
        final TestPki.Leaf p384 = PKI.issueLeaf(TestPki.LeafSpec.defaults().withKeyType(TestPki.KeyType.EC_P384));
        final String jwt = factory.signedRequestObject(tx(), hashConfig(), handle(p384, JWSAlgorithm.ES384), BASE);

        assertThat(SignedJWT.parse(jwt).getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.ES384);
        assertThat(wallet.verifyRequest("x509_hash:" + expectedHash(p384.certificate()), "uri", jwt, NOW).clientId())
                .startsWith("x509_hash:");
    }

    // ------------------------------------------------------------------------------------------------ claims

    @Test
    void claims_carryTheProtocolParameters() throws Exception {
        final JsonNode p = payload(factory.signedRequestObject(tx(), hashConfig(), key, BASE));

        assertThat(p.get("response_type").asText()).isEqualTo("vp_token");
        assertThat(p.get("response_mode").asText()).isEqualTo("direct_post.jwt");
        assertThat(p.get("response_uri").asText())
                .isEqualTo("https://verifier.example.eu/realms/acme/oid4vp/eudi/response/resp-R2VuZXJhdGVk");
        assertThat(p.get("nonce").asText()).isEqualTo(NONCE);
        assertThat(p.get("aud").asText()).isEqualTo("https://self-issued.me/v2");
        assertThat(p.get("dcql_query")).isEqualTo(JSON.readTree(dcql()));
        assertThat(p.has("iss")).isFalse();
        assertThat(p.has("nbf")).isFalse();
    }

    @Test
    void iatIsNow_andExpIsTheTransactionExpiry() throws Exception {
        final JWTClaimsSet claims = SignedJWT.parse(factory.signedRequestObject(tx(), hashConfig(), key, BASE))
                .getJWTClaimsSet();

        assertThat(claims.getIssueTime()).isEqualTo(Date.from(NOW));
        assertThat(claims.getExpirationTime()).isEqualTo(Date.from(EXPIRES));
        assertThat(claims.getExpirationTime().toInstant()).isBeforeOrEqualTo(tx().expiresAt());
    }

    @Test
    void expIsNeverLaterThanAFractionalTransactionExpiry() throws Exception {
        final WalletTransaction base = tx();
        final WalletTransaction fractional = new WalletTransaction(base.transactionId(), base.sameDeviceRequestId(),
                base.crossDeviceRequestId(), base.responseId(), base.realmId(), base.providerAlias(),
                base.helixState(), base.browserBindingHash(), base.nonce(), base.encryptionJwkJson(),
                base.dcqlQueryJson(), null, base.status(), null, null, null, base.createdAt(),
                EXPIRES.plusMillis(999));

        final Date exp = SignedJWT.parse(factory.signedRequestObject(fractional, hashConfig(), key, BASE))
                .getJWTClaimsSet().getExpirationTime();

        assertThat(exp.toInstant()).isBeforeOrEqualTo(fractional.expiresAt());
    }

    @Test
    void anExpiredTransactionIsRefused() {
        final AuthorizationRequestFactory late =
                new AuthorizationRequestFactory(Clock.fixed(EXPIRES, ZoneOffset.UTC));

        assertThatThrownBy(() -> late.signedRequestObject(tx(), hashConfig(), key, BASE))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void state_isTheHashOfTheTransactionId_neverHelixState() throws Exception {
        final String jwt = factory.signedRequestObject(tx(), hashConfig(), key, BASE);
        final String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(TX_ID.getBytes(StandardCharsets.UTF_8)));

        assertThat(payload(jwt).get("state").asText()).isEqualTo(expected);
        assertThat(AuthorizationRequestFactory.walletState(TX_ID)).isEqualTo(expected);
        final String decoded = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(decoded).doesNotContain(HELIX_STATE).doesNotContain("binding-hash");
    }

    // ------------------------------------------------------------------------------------------------ client_metadata

    @Test
    void clientMetadataJwks_holdsOnlyThePublicTransactionKey() throws Exception {
        final String jwt = factory.signedRequestObject(tx(), hashConfig(), key, BASE);
        final JsonNode keys = payload(jwt).get("client_metadata").get("jwks").get("keys");

        assertThat(keys).hasSize(1);
        final JsonNode jwk = keys.get(0);
        assertThat(jwk.get("kty").asText()).isEqualTo("EC");
        assertThat(jwk.get("crv").asText()).isEqualTo("P-256");
        assertThat(jwk.get("use").asText()).isEqualTo("enc");
        assertThat(jwk.get("alg").asText()).isEqualTo("ECDH-ES");
        assertThat(jwk.get("kid").asText()).isEqualTo(KID);
        assertThat(jwk.get("x").asText()).isEqualTo(encKey.getX().toString());
        assertThat(jwk.get("y").asText()).isEqualTo(encKey.getY().toString());
        assertThat(jwk.has("d")).isFalse();
        assertThat(payload(jwt).findValues("d")).isEmpty();
        final String decoded = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(decoded).doesNotContain(encKey.getD().toString());
    }

    @Test
    void storedKeyWithoutUseAndAlg_isPublishedWithThem() throws Exception {
        final ECKey bare = new ECKeyGenerator(Curve.P_256).keyID("bare").generate();
        final JsonNode jwk = payload(factory.signedRequestObject(tx("s", "c", bare.toJSONString()), hashConfig(),
                key, BASE)).get("client_metadata").get("jwks").get("keys").get(0);

        assertThat(jwk.get("use").asText()).isEqualTo("enc");
        assertThat(jwk.get("alg").asText()).isEqualTo("ECDH-ES");
        assertThat(jwk.get("kid").asText()).isEqualTo("bare");
    }

    @Test
    void transactionWithoutAUsableEncryptionKey_isRefused() throws Exception {
        final String noKid = new ECKeyGenerator(Curve.P_256).generate().toJSONString();
        final String wrongCurve = new ECKeyGenerator(Curve.P_384).keyID("k").generate().toJSONString();
        final String signingKey = new ECKeyGenerator(Curve.P_256).keyID("k").keyUse(KeyUse.SIGNATURE).generate()
                .toJSONString();

        for (final String bad : new String[]{null, "not json", noKid, wrongCurve, signingKey}) {
            assertThatThrownBy(() -> factory.signedRequestObject(tx("s", "c", bad), hashConfig(), key, BASE))
                    .as(String.valueOf(bad)).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void clientMetadata_listsBothHaipEncValues_andTheNotesVpFormats() throws Exception {
        final JsonNode metadata = payload(factory.signedRequestObject(tx(), hashConfig(), key, BASE))
                .get("client_metadata");

        assertThat(metadata.get("encrypted_response_enc_values_supported"))
                .isEqualTo(JSON.readTree("[\"A128GCM\",\"A256GCM\"]"));
        assertThat(metadata.get("vp_formats_supported")).isEqualTo(JSON.readTree("""
                {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
                               "kb-jwt_alg_values": ["ES256", "ES384", "ES512"]},
                 "mso_mdoc":  {"issuerauth_alg_values": [-7, -9, -35, -51, -36, -52],
                               "deviceauth_alg_values": [-7, -9, -35, -51, -36, -52]}}"""));
        assertThat(metadata.size()).isEqualTo(3);
    }

    @Test
    void vpFormats_followTheConfiguredFormats() throws Exception {
        final WalletProviderConfig sdJwtOnly = config(Map.of("credentialFormats", "[\"dc+sd-jwt\"]"));
        final JsonNode formats = payload(factory.signedRequestObject(tx(), sdJwtOnly, key, BASE))
                .get("client_metadata").get("vp_formats_supported");

        assertThat(formats.fieldNames()).toIterable().containsExactly("dc+sd-jwt");
    }

    @Test
    void devDirectPost_isUnencrypted_soNoEncryptionMetadataIsSent() throws Exception {
        final JsonNode p = payload(factory.signedRequestObject(tx(), config(Map.of("responseMode", "direct_post")),
                key, BASE));

        assertThat(p.get("response_mode").asText()).isEqualTo("direct_post");
        assertThat(p.get("client_metadata").has("jwks")).isFalse();
        assertThat(p.get("client_metadata").has("encrypted_response_enc_values_supported")).isFalse();
        assertThat(p.get("client_metadata").has("vp_formats_supported")).isTrue();
    }

    @Test
    void sanDns_refusesAResponseUriOnAnotherHost() {
        assertThatThrownBy(() -> factory.signedRequestObject(tx(), sanConfig(), key, "https://other.example.eu"))
                .isInstanceOf(IllegalStateException.class);
    }

    // ------------------------------------------------------------------------------------------------ URLs

    @Test
    void responseAndRequestUris_followTheRealmPrefixedRoutes() {
        final WalletTransaction tx = tx();

        assertThat(AuthorizationRequestFactory.responseUri(BASE + "/", tx))
                .isEqualTo(BASE + "/realms/acme/oid4vp/eudi/response/resp-R2VuZXJhdGVk");
        assertThat(AuthorizationRequestFactory.requestUri(BASE, tx, Flow.SAME_DEVICE))
                .isEqualTo(BASE + "/realms/acme/oid4vp/eudi/request/same-U2FtZURldmljZQ");
        assertThat(AuthorizationRequestFactory.requestUri(BASE, tx, Flow.CROSS_DEVICE))
                .isEqualTo(BASE + "/realms/acme/oid4vp/eudi/request/cross-Q3Jvc3NEZXZpY2U");
    }

    @Test
    void invocationUrl_usesTheDefaultHaipScheme_andTheFlowsRequestId() throws Exception {
        final WalletTransaction tx = tx();
        final String same = factory.invocationUrl(tx, hashConfig(), key, Flow.SAME_DEVICE, BASE);
        final String cross = factory.invocationUrl(tx, hashConfig(), key, Flow.CROSS_DEVICE, BASE);

        final String clientId = "x509_hash:" + expectedHash(LEAF.certificate());
        assertThat(same).isEqualTo("haip-vp://?client_id=x509_hash%3A" + expectedHash(LEAF.certificate())
                + "&request_uri=https%3A%2F%2Fverifier.example.eu%2Frealms%2Facme%2Foid4vp%2Feudi%2Frequest%2F"
                + "same-U2FtZURldmljZQ");
        assertThat(TestWallet.invocationParameters(cross)).containsExactly(
                Map.entry("client_id", clientId),
                Map.entry("request_uri", BASE + "/realms/acme/oid4vp/eudi/request/cross-Q3Jvc3NEZXZpY2U"));
    }

    @Test
    void invocationUrl_usesTheConfiguredScheme() {
        assertThat(factory.invocationUrl(tx(), config(Map.of("invocationScheme", "openid4vp")), key,
                Flow.SAME_DEVICE, BASE)).startsWith("openid4vp://?client_id=");
    }

    @Test
    void invocationUrl_addsRequestUriMethodOnlyForPost() {
        assertThat(factory.invocationUrl(tx(), hashConfig(), key, Flow.SAME_DEVICE, BASE))
                .doesNotContain("request_uri_method");
        final String post = factory.invocationUrl(tx(), config(Map.of("requestUriMethod", "post")), key,
                Flow.SAME_DEVICE, BASE);
        assertThat(TestWallet.invocationParameters(post)).containsEntry("request_uri_method", "post");
    }

    @Test
    void invocationUrl_percentEncodesReservedCharacters_rfc3986NotForm() {
        final String id = "a b+c/d?e&f=g#h%é";
        final String base = "https://verifier.example.eu:8443/id%20p;v=1";
        final WalletTransaction tx = tx(id, "cross", encKey.toJSONString());
        final String url = factory.invocationUrl(tx, sanConfig(), key, Flow.SAME_DEVICE, base);

        final String query = url.substring(url.indexOf('?') + 1);
        final String[] params = query.split("&");
        assertThat(params).hasSize(2);
        for (final String param : params) {
            assertThat(param.chars().filter(c -> c == '=').count()).as(param).isEqualTo(1);
            assertThat(param.substring(param.indexOf('=') + 1)).as(param)
                    .matches("[A-Za-z0-9._~%-]*");
        }
        assertThat(query).contains("%2520", "%252B").doesNotContain("+", " ");
        assertThat(url).startsWith("haip-vp://?client_id=x509_san_dns%3Averifier.example.eu&request_uri="
                + "https%3A%2F%2Fverifier.example.eu%3A8443%2Fid%2520p%3Bv%3D1%2F");
        final String requestUri = TestWallet.invocationParameters(url).get("request_uri");
        assertThat(requestUri).isEqualTo(AuthorizationRequestFactory.requestUri(base, tx, Flow.SAME_DEVICE))
                .isEqualTo("https://verifier.example.eu:8443/id%20p;v=1/realms/acme/oid4vp/eudi/request/"
                        + "a%20b%2Bc%2Fd%3Fe%26f%3Dg%23h%25%C3%A9");
    }

    // ------------------------------------------------------------------------------------------------ TestWallet

    @Test
    void walletRefusesARequestWhoseClientIdDoesNotBindToTheLeaf() throws Exception {
        final TestPki.Leaf other = PKI.issueLeaf(TestPki.LeafSpec.defaults().withDnsNames("other.example.eu"));
        final String jwt = factory.signedRequestObject(tx(), hashConfig(), handle(other, JWSAlgorithm.ES256), BASE);
        final String forged = resign(jwt, other, claims -> claims.claim("client_id",
                "x509_hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32])));

        assertThatThrownBy(() -> wallet.verifyRequest(
                "x509_hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]), "u", forged, NOW))
                .hasMessageContaining("x509_hash");
        final String sanJwt = factory.signedRequestObject(tx(), sanConfig(), handle(other, JWSAlgorithm.ES256), BASE);
        assertThatThrownBy(() -> wallet.verifyRequest("x509_san_dns:" + HOST, "u", sanJwt, NOW))
                .hasMessageContaining("SAN");
    }

    @Test
    void walletRefusesASignatureNotByTheX5cLeaf_aWrongTyp_aWrongAud_andAnExpiredRequest() throws Exception {
        final String jwt = factory.signedRequestObject(tx(), hashConfig(), key, BASE);
        final String clientId = AuthorizationRequestFactory.clientId(hashConfig(), key);
        final TestPki.Leaf other = PKI.issueLeaf(TestPki.LeafSpec.defaults());

        final String foreignSignature = resignKeepingHeader(jwt, other);
        assertThatThrownBy(() -> wallet.verifyRequest(clientId, "u", foreignSignature, NOW))
                .hasMessageContaining("signature");
        final String wrongAud = resign(jwt, LEAF, c -> c.audience("https://verifier.example.eu"));
        assertThatThrownBy(() -> wallet.verifyRequest(clientId, "u", wrongAud, NOW)).hasMessageContaining("aud");
        assertThatThrownBy(() -> wallet.verifyRequest(clientId, "u", jwt, EXPIRES)).hasMessageContaining("expired");
        final String wrongTyp = resignWithHeader(jwt, LEAF, new JOSEObjectType("JWT"));
        assertThatThrownBy(() -> wallet.verifyRequest(clientId, "u", wrongTyp, NOW)).hasMessageContaining("typ");
    }

    // ------------------------------------------------------------------------------------------------ round trip

    @Test
    void walletResponse_decryptsWithTheTransactionKey_andCarriesTheWalletState() {
        final VerifiedRequest request = walletRun(tx(), hashConfig(), Flow.SAME_DEVICE);
        final String jwe = wallet.respond(request, Map.of("pid_sd_jwt", List.of("presentation")));

        final DecryptedResponse response = new VpResponseDecryptor().decrypt(jwe, encKey,
                AuthorizationRequestFactory.RESPONSE_ENC_VALUES);

        assertThat(response.state()).isEqualTo(AuthorizationRequestFactory.walletState(TX_ID));
        assertThat(response.vpToken().get("pid_sd_jwt").get(0).asText()).isEqualTo("presentation");
        assertThat(parseJwe(jwe).getHeader().getEncryptionMethod()).isEqualTo(EncryptionMethod.A256GCM);
        assertThat(parseJwe(jwe).getHeader().getKeyID()).isEqualTo(KID);
        assertThat(AuthorizationRequestFactory.RESPONSE_ENC_VALUES)
                .isEqualTo(Set.of(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM));
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static JWEObject parseJwe(final String jwe) {
        try {
            return JWEObject.parse(jwe);
        } catch (final java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String resign(final String jwt, final TestPki.Leaf signer,
            final java.util.function.Consumer<JWTClaimsSet.Builder> change) throws Exception {
        final SignedJWT parsed = SignedJWT.parse(jwt);
        final JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder(parsed.getJWTClaimsSet());
        change.accept(claims);
        final JWSHeader header = new JWSHeader.Builder(parsed.getHeader())
                .x509CertChain(x5c(signer)).build();
        final SignedJWT out = new SignedJWT(header, claims.build());
        out.sign(new ECDSASigner((ECPrivateKey) signer.privateKey()));
        return out.serialize();
    }

    private static String resignWithHeader(final String jwt, final TestPki.Leaf signer, final JOSEObjectType typ)
            throws Exception {
        final SignedJWT parsed = SignedJWT.parse(jwt);
        final SignedJWT out = new SignedJWT(new JWSHeader.Builder(parsed.getHeader()).type(typ).build(),
                parsed.getJWTClaimsSet());
        out.sign(new ECDSASigner((ECPrivateKey) signer.privateKey()));
        return out.serialize();
    }

    /** Same header (so the x5c still names the verifier leaf) but signed by another key. */
    private static String resignKeepingHeader(final String jwt, final TestPki.Leaf otherSigner) throws Exception {
        final SignedJWT parsed = SignedJWT.parse(jwt);
        final SignedJWT out = new SignedJWT(parsed.getHeader(), parsed.getJWTClaimsSet());
        out.sign(new ECDSASigner((ECPrivateKey) otherSigner.privateKey()));
        return out.serialize();
    }

    private static List<com.nimbusds.jose.util.Base64> x5c(final TestPki.Leaf leaf) throws Exception {
        final List<com.nimbusds.jose.util.Base64> chain = new java.util.ArrayList<>();
        for (final X509Certificate cert : leaf.chain()) {
            chain.add(com.nimbusds.jose.util.Base64.encode(cert.getEncoded()));
        }
        return chain;
    }
}
