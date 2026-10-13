/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link SessionTranscripts} against the official OpenID4VP 1.0 Appendix B.2.6.1 example
 * ({@code wallet/vectors/openid4vp/openid4vp-1.0-B.2.6.1-handover.json}): the handover info, handover and
 * SessionTranscript bytes must match byte for byte. The remaining cases compare against Jackson's CBOR writer (via
 * {@link TestWallet#cbor}), which is independent of the production encoder.
 */
class SessionTranscriptsTest {

    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode vector;

    @BeforeAll
    static void loadVector() throws Exception {
        try (InputStream in = SessionTranscriptsTest.class.getResourceAsStream(
                "/wallet/vectors/openid4vp/openid4vp-1.0-B.2.6.1-handover.json")) {
            vector = new ObjectMapper().readTree(in);
        }
    }

    private static String input(final String name) {
        return vector.get("inputs").get(name).asText();
    }

    private static byte[] expected(final String name) {
        return HEX.parseHex(vector.get("expected").get(name).asText());
    }

    /** RFC 7638 SHA-256 thumbprint of the vector's JWK, computed by Nimbus and checked against the vector. */
    private static byte[] thumbprint() throws Exception {
        final ECKey jwk = ECKey.parse(vector.get("inputs").get("encryption_jwk").toString());
        final byte[] thumbprint = jwk.computeThumbprint("SHA-256").decode();
        assertThat(thumbprint).isEqualTo(expected("jwk_thumbprint_sha256_hex"));
        return thumbprint;
    }

    @Test
    void handoverInfoMatchesTheSpecVector() throws Exception {
        assertThat(SessionTranscripts.handoverInfo(input("client_id"), input("nonce"), thumbprint(),
                input("response_uri"))).isEqualTo(expected("openid4vp_handover_info_cbor_hex"));
    }

    @Test
    void handoverMatchesTheSpecVector() throws Exception {
        assertThat(SessionTranscripts.handover(input("client_id"), input("nonce"), thumbprint(),
                input("response_uri"))).isEqualTo(expected("openid4vp_handover_cbor_hex"));
    }

    @Test
    void sessionTranscriptMatchesTheSpecVector() throws Exception {
        assertThat(SessionTranscripts.openId4VpRedirect(input("client_id"), input("nonce"), thumbprint(),
                input("response_uri"))).isEqualTo(expected("session_transcript_cbor_hex"));
    }

    @Test
    void unencryptedResponseHasANullThumbprint() {
        final byte[] info = SessionTranscripts.handoverInfo("x509_hash:abc", "n-1", null, "https://rp.example/r");

        assertThat(info).isEqualTo(TestWallet.cbor(Arrays.asList("x509_hash:abc", "n-1", null,
                "https://rp.example/r")));
        assertThat(info[info.length - 22]).isEqualTo((byte) 0xf6); // CBOR null, then the 21-byte uri item
    }

    @Test
    void transcriptIsNullNullHandoverWithTheSha256OfTheInfo() {
        final byte[] thumbprint = new byte[32];
        Arrays.fill(thumbprint, (byte) 7);
        final byte[] info = TestWallet.cbor(List.of("client", "nonce", thumbprint, "https://rp.example/r"));
        final byte[] handover = TestWallet.cbor(List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info)));

        assertThat(SessionTranscripts.openId4VpRedirect("client", "nonce", thumbprint, "https://rp.example/r"))
                .isEqualTo(TestWallet.cbor(Arrays.asList(null, null,
                        List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info)))))
                .endsWith(handover);
    }

    @Test
    void longAndNonAsciiStringsUseTheirUtf8LengthHeads() {
        final String nonce = "é".repeat(150); // 300 UTF-8 bytes: a two-byte length head (79 01 2c)

        assertThat(SessionTranscripts.handoverInfo("c", nonce, null, "u"))
                .isEqualTo(TestWallet.cbor(Arrays.asList("c", nonce, null, "u")));
    }

    @Test
    void textOver64KiBUsesAFourByteDefiniteLengthHead() {
        // Jackson writes such text as indefinite-length chunks, so the expected head is written out: 7a 00 01 11 70
        final byte[] info = SessionTranscripts.handoverInfo("x".repeat(70_000), "n", null, "u");

        assertThat(Arrays.copyOfRange(info, 0, 6)).isEqualTo(new byte[] {(byte) 0x84, 0x7a, 0x00, 0x01, 0x11, 0x70});
        assertThat(info).hasSize(1 + 5 + 70_000 + 2 + 1 + 2);
    }

    @Test
    void deviceAuthenticationBytesEmbedTheTranscriptAndNameSpacesByteExact() {
        final byte[] transcript = SessionTranscripts.openId4VpRedirect("c", "n", null, "u");
        final byte[] deviceNameSpaces = TestWallet.cbor(new TestWallet.CborTag(24, TestWallet.cbor(java.util.Map.of())));

        // Jackson cannot embed already-encoded CBOR, so the expected array is assembled from its encoded parts.
        final java.io.ByteArrayOutputStream expectedInner = new java.io.ByteArrayOutputStream();
        expectedInner.write(0x84);
        expectedInner.writeBytes(TestWallet.cbor("DeviceAuthentication"));
        expectedInner.writeBytes(transcript);
        expectedInner.writeBytes(TestWallet.cbor("eu.europa.ec.eudi.pid.1"));
        expectedInner.writeBytes(deviceNameSpaces);

        assertThat(SessionTranscripts.deviceAuthenticationBytes(transcript, "eu.europa.ec.eudi.pid.1",
                deviceNameSpaces)).isEqualTo(TestWallet.cbor(new TestWallet.CborTag(24,
                        expectedInner.toByteArray())));
    }
}
