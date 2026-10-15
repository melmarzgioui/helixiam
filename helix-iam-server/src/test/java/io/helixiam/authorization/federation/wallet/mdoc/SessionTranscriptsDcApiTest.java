/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The DC API SessionTranscript ({@link SessionTranscripts#openId4VpDcApi}) against the official OpenID4VP 1.0
 * Appendix B.2.6.2 example ({@code wallet/vectors/openid4vp/openid4vp-1.0-B.2.6.2-dc-api-handover.json}), byte for
 * byte, plus the unencrypted ({@code dc_api}) case against Jackson's independent CBOR writer.
 */
class SessionTranscriptsDcApiTest {

    private static final HexFormat HEX = HexFormat.of();

    private static JsonNode vector;

    @BeforeAll
    static void loadVector() throws Exception {
        try (InputStream in = SessionTranscriptsDcApiTest.class.getResourceAsStream(
                "/wallet/vectors/openid4vp/openid4vp-1.0-B.2.6.2-dc-api-handover.json")) {
            vector = new ObjectMapper().readTree(in);
        }
    }

    private static String input(final String name) {
        return vector.get("inputs").get(name).asText();
    }

    private static byte[] expected(final String name) {
        return HEX.parseHex(vector.get("expected").get(name).asText());
    }

    private static byte[] thumbprint() throws Exception {
        final ECKey jwk = ECKey.parse(vector.get("inputs").get("encryption_jwk").toString());
        final byte[] thumbprint = jwk.computeThumbprint("SHA-256").decode();
        assertThat(thumbprint).isEqualTo(expected("jwk_thumbprint_sha256_hex"));
        return thumbprint;
    }

    @Test
    void handoverInfoMatchesTheSpecVector() throws Exception {
        assertThat(SessionTranscripts.dcApiHandoverInfo(input("origin"), input("nonce"), thumbprint()))
                .isEqualTo(expected("openid4vp_dc_api_handover_info_cbor_hex"));
    }

    @Test
    void handoverMatchesTheSpecVector() throws Exception {
        assertThat(SessionTranscripts.dcApiHandover(input("origin"), input("nonce"), thumbprint()))
                .isEqualTo(expected("openid4vp_dc_api_handover_cbor_hex"));
    }

    @Test
    void sessionTranscriptMatchesTheSpecVector() throws Exception {
        assertThat(SessionTranscripts.openId4VpDcApi(input("origin"), input("nonce"), thumbprint()))
                .isEqualTo(expected("session_transcript_cbor_hex"));
    }

    @Test
    void dcApiWithoutEncryptionHasANullThumbprint() {
        final byte[] info = TestWallet.cbor(Arrays.asList("https://rp.example", "n-1", null));

        assertThat(SessionTranscripts.openId4VpDcApi("https://rp.example", "n-1", null))
                .isEqualTo(TestWallet.cbor(Arrays.asList(null, null,
                        List.of("OpenID4VPDCAPIHandover", TestWallet.sha("SHA-256", info)))));
    }

    @Test
    void differsFromTheRedirectTranscriptForTheSameValues() {
        assertThat(SessionTranscripts.openId4VpDcApi("https://rp.example", "n", null))
                .isNotEqualTo(SessionTranscripts.openId4VpRedirect("https://rp.example", "n", null,
                        "https://rp.example"));
    }

    @Test
    void anOriginPrefixedWithOriginColonIsRefused() {
        // B.2.6.2: the origin "MUST NOT be prefixed with origin:"; a caller passing the audience form is a bug.
        assertThatThrownBy(() -> SessionTranscripts.openId4VpDcApi("origin:https://rp.example", "n", null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
