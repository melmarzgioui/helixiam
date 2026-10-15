/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.CompressionAlgorithm;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.text.ParseException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link VpResponseDecryptor}: every controller ruling for the {@code direct_post.jwt} encrypted response
 * (docs/eudi-wallet-spec-notes.md §1.3, §1.7; HAIP §2.1) has a positive and at least one negative test. Each
 * negative test changes exactly one thing in an otherwise valid encrypted response.
 */
class VpResponseDecryptorTest {

    private static final String KID = "txn-key-1";
    private static final Set<EncryptionMethod> ALLOWED_ENC = Set.of(EncryptionMethod.A128GCM,
            EncryptionMethod.A256GCM);

    private final VpResponseDecryptor decryptor = new VpResponseDecryptor();

    private static ECKey transactionKey() throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(KID).algorithm(JWEAlgorithm.ECDH_ES).generate();
    }

    private static String encrypt(final ECKey recipientPublicKey, final String kid, final EncryptionMethod enc,
            final String payloadJson) throws Exception {
        final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc).keyID(kid).build();
        final JWEObject jwe = new JWEObject(header, new Payload(payloadJson));
        jwe.encrypt(new ECDHEncrypter(recipientPublicKey));
        return jwe.serialize();
    }

    /** Builds a syntactically valid compact JWE with an arbitrary, never-decrypted body, to test header checks. */
    private static String withHeaderOnly(final JWEHeader header) throws ParseException {
        final Base64URL filler = Base64URL.encode(new byte[] {1, 2, 3, 4});
        return new JWEObject(header.toBase64URL(), Base64URL.encode(new byte[0]), filler, filler, filler)
                .serialize();
    }

    // ---- round trip ----

    @Test
    void roundTripsA128Gcm() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"my_credential\":[\"eyJhbGci\"]},\"state\":\"s1\"}");

        final DecryptedResponse response = decryptor.decrypt(jwe, key, ALLOWED_ENC);

        assertThat(response.state()).isEqualTo("s1");
        assertThat(response.vpToken().get("my_credential").get(0).asText()).isEqualTo("eyJhbGci");
    }

    @Test
    void roundTripsA256GcmWithNoState() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A256GCM,
                "{\"vp_token\":{\"my_credential\":[\"abc\"]}}");

        final DecryptedResponse response = decryptor.decrypt(jwe, key, ALLOWED_ENC);

        assertThat(response.state()).isNull();
        assertThat(response.vpToken().get("my_credential").get(0).asText()).isEqualTo("abc");
    }

    @Test
    void theOpenId4VpSpecVectorDecrypts() throws Exception {
        final JsonNode vector;
        try (InputStream in = VpResponseDecryptorTest.class
                .getResourceAsStream("/wallet/vectors/openid4vp/openid4vp-1.0-8.3-encrypted-response.json")) {
            vector = new ObjectMapper().readTree(in);
        }
        final ECKey key = ECKey.parse(vector.get("verifier_private_jwk").toString());
        final String jwe = vector.get("response_jwe").asText();

        final DecryptedResponse response = decryptor.decrypt(jwe, key, ALLOWED_ENC);

        final JsonNode expectedPayload = vector.get("expected_payload");
        assertThat(response.vpToken()).isEqualTo(expectedPayload.get("vp_token"));
    }

    // ---- header checks ----

    @Test
    void keyWrappingAlgIsNotAllowed() throws Exception {
        final ECKey key = transactionKey();
        final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A128KW, EncryptionMethod.A128GCM)
                .keyID(KID).build();

        assertThatThrownBy(() -> decryptor.decrypt(withHeaderOnly(header), key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void encNotInAllowedSetIsNotAllowed() throws Exception {
        final ECKey key = transactionKey();
        final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128CBC_HS256)
                .keyID(KID).build();

        assertThatThrownBy(() -> decryptor.decrypt(withHeaderOnly(header), key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void algMustMatchTheTransactionKeysDeclaredAlgWhenSet() throws Exception {
        final ECKey base = transactionKey();
        final ECKey keyWithDifferentAlg = new ECKey.Builder(base).algorithm(new Algorithm("ECDH-ES+A128KW")).build();
        final String jwe = encrypt(base.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]}}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, keyWithDifferentAlg, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void zipHeaderIsNotAllowed() throws Exception {
        final ECKey key = transactionKey();
        final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                .keyID(KID).compressionAlgorithm(CompressionAlgorithm.DEF).build();
        final JWEObject jwe = new JWEObject(header, new Payload("{\"vp_token\":{\"c\":[\"x\"]}}"));
        jwe.encrypt(new ECDHEncrypter(key.toPublicJWK()));

        assertThatThrownBy(() -> decryptor.decrypt(jwe.serialize(), key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void epkOnADifferentCurveFailsDecryption() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]}}");
        final JWEObject parsed = JWEObject.parse(jwe);
        final ECKey otherCurveEpk = new ECKeyGenerator(Curve.P_384).generate().toPublicJWK();
        final JWEHeader badEpkHeader = new JWEHeader.Builder(parsed.getHeader()).ephemeralPublicKey(otherCurveEpk)
                .build();
        final String tampered = new JWEObject(badEpkHeader.toBase64URL(), parsed.getEncryptedKey(), parsed.getIV(),
                parsed.getCipherText(), parsed.getAuthTag()).serialize();

        assertThatThrownBy(() -> decryptor.decrypt(tampered, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.DECRYPTION_FAILED);
    }

    // ---- kid ----

    @Test
    void missingKidFailsDecryption() throws Exception {
        final ECKey key = transactionKey();
        final JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM).build();
        final JWEObject jwe = new JWEObject(header, new Payload("{\"vp_token\":{\"c\":[\"x\"]}}"));
        jwe.encrypt(new ECDHEncrypter(key.toPublicJWK()));

        assertThatThrownBy(() -> decryptor.decrypt(jwe.serialize(), key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.DECRYPTION_FAILED);
    }

    @Test
    void wrongKidFailsDecryption() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), "some-other-kid", EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]}}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.DECRYPTION_FAILED);
    }

    @Test
    void encryptedToAnotherKeyFailsDecryption() throws Exception {
        final ECKey key = transactionKey();
        final ECKey otherKey = new ECKeyGenerator(Curve.P_256).generate();
        // Same kid as the real transaction key, but encrypted to a different recipient key entirely.
        final String jwe = encrypt(otherKey.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]}}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.DECRYPTION_FAILED);
    }

    @Test
    void decryptionFailureMessageIsOpaque() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), "wrong-kid", EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]}}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .hasMessageNotContaining("Nimbus")
                .hasMessageNotContaining("tag")
                .hasMessageNotContaining("MAC")
                .hasMessageNotContaining("key");
    }

    // ---- size ----

    @Test
    void oversizeCompactJweIsRejectedBeforeParsing() throws Exception {
        final ECKey key = transactionKey();
        final String huge = "x".repeat(300 * 1024);

        assertThatThrownBy(() -> decryptor.decrypt(huge, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.LIMIT_EXCEEDED);
    }

    // ---- payload shape ----

    @Test
    void vpTokenThatIsAStringIsInvalid() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":\"not-an-object\"}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void missingVpTokenIsInvalid() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM, "{\"state\":\"s1\"}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void nonStringStateIsInvalid() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]},\"state\":123}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void nullStateIsAbsentState() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"c\":[\"x\"]},\"state\":null}");

        final DecryptedResponse response = decryptor.decrypt(jwe, key, ALLOWED_ENC);

        assertThat(response.state()).isNull();
    }

    @Test
    void topLevelArrayIsInvalid() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM, "[\"not\",\"an\",\"object\"]");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void duplicateTopLevelMemberIsInvalid() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"vp_token\":{\"a\":[\"1\"]},\"vp_token\":{\"b\":[\"2\"]}}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    // ---- wallet error response (§8.5) ----

    @Test
    void walletAccessDeniedIsSurfacedDistinctly() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"error\":\"access_denied\",\"error_description\":\"nope\",\"state\":\"s1\"}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.WALLET_ACCESS_DENIED);
    }

    @Test
    void anyOtherWalletErrorIsSurfacedGenerically() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"error\":\"invalid_request\",\"state\":\"s1\"}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.WALLET_ERROR);
    }

    @Test
    void walletErrorDescriptionNeverLeaksIntoTheExceptionMessage() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM,
                "{\"error\":\"access_denied\",\"error_description\":\"super-secret-detail-should-not-leak\"}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .hasMessageNotContaining("super-secret-detail-should-not-leak");
    }

    @Test
    void nonStringErrorIsInvalid() throws Exception {
        final ECKey key = transactionKey();
        final String jwe = encrypt(key.toPublicJWK(), KID, EncryptionMethod.A128GCM, "{\"error\":123}");

        assertThatThrownBy(() -> decryptor.decrypt(jwe, key, ALLOWED_ENC))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }
}
