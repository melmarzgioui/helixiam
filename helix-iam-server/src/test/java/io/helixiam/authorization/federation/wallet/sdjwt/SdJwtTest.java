/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link SdJwt#parse} splits the compact serialisation (RFC 9901 §4) and must keep every segment byte-exact, because
 * {@link SdJwt#presentationWithoutKbJwt()} is the {@code sd_hash} input (RFC 9901 §4.3.1). Vectors: see
 * {@code src/test/resources/wallet/vectors/SOURCES.md}.
 */
class SdJwtTest {

    static final int MAX_DISCLOSURES = 100;
    static final int MAX_JWT_BYTES = 64 * 1024;

    static String vector(String name) {
        try (InputStream in = SdJwtTest.class.getResourceAsStream("/wallet/vectors/sd-jwt/" + name)) {
            if (in == null) {
                throw new IllegalStateException("missing vector " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII).strip();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> expected(String name) {
        try {
            return com.nimbusds.jose.util.JSONObjectUtils.parse(vector(name));
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static SdJwt parse(String s) {
        return SdJwt.parse(s, MAX_DISCLOSURES, MAX_JWT_BYTES);
    }

    private static void assertCode(Runnable r, WalletErrorCode code) {
        assertThatThrownBy(r::run).isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(code));
    }

    // ---------------------------------------------------------------- positive (RFC 9901 vectors)

    @Test
    void splitsSdJwtWithKbJwt_rfc9901_5_2() {
        String raw = vector("rfc9901-5.2-sd-jwt-kb.txt");
        SdJwt sdJwt = parse(raw);

        assertThat(sdJwt.issuerJwt()).isEqualTo(raw.substring(0, raw.indexOf('~')));
        assertThat(sdJwt.disclosures()).hasSize(4);
        assertThat(sdJwt.disclosures().get(0)).isEqualTo("WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd");
        assertThat(sdJwt.keyBindingJwt()).isEqualTo(raw.substring(raw.lastIndexOf('~') + 1)).startsWith("eyJ");
    }

    @Test
    void presentationWithoutKbJwtIsTheExactSdHashInput_rfc9901_5_2() {
        String raw = vector("rfc9901-5.2-sd-jwt-kb.txt");
        SdJwt sdJwt = parse(raw);

        assertThat(sdJwt.presentationWithoutKbJwt()).isEqualTo(raw.substring(0, raw.lastIndexOf('~') + 1));
        String documented = (String) ((Map<?, ?>) expected("rfc9901-5.2-expected.json").get("key_binding_jwt_payload"))
                .get("sd_hash");
        assertThat(sdJwt.sdHash("sha-256")).isEqualTo(documented).isEqualTo("0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY");
    }

    @Test
    void sdHashMatchesTheDocumentedValue_rfc9901_A3() {
        SdJwt sdJwt = parse(vector("rfc9901-A.3-sd-jwt-vc-kb.txt"));
        assertThat(sdJwt.sdHash("sha-256")).isEqualTo("PjMYfM07VbJdMxLIluvRNb88JFljSX4n-G43Uc_BSRM");
    }

    @Test
    void sdHashUsesTheGivenAlgorithmNotAlwaysSha256() {
        SdJwt sdJwt = parse(vector("rfc9901-5.2-sd-jwt-kb.txt"));
        assertThat(sdJwt.sdHash("sha-384"))
                .isEqualTo(SdJwtDisclosures.digest(sdJwt.presentationWithoutKbJwt(), "sha-384"))
                .hasSize(64); // 48 bytes, base64url without padding
        assertCode(() -> sdJwt.sdHash("md5"), WalletErrorCode.ALGORITHM_NOT_ALLOWED);
    }

    @Test
    void sdJwtWithoutKbJwtEndsInTildeAndHasNullKb_rfc9901_5_1() {
        String raw = vector("rfc9901-5.1-sd-jwt.txt");
        assertThat(raw).endsWith("~");
        SdJwt sdJwt = parse(raw);

        assertThat(sdJwt.keyBindingJwt()).isNull();
        assertThat(sdJwt.disclosures()).hasSize(10);
        assertThat(sdJwt.presentationWithoutKbJwt()).isEqualTo(raw);
    }

    @Test
    void issuerJwtWithNoDisclosures() {
        String issuer = parse(vector("rfc9901-5.1-sd-jwt.txt")).issuerJwt();
        SdJwt sdJwt = parse(issuer + "~");
        assertThat(sdJwt.disclosures()).isEmpty();
        assertThat(sdJwt.keyBindingJwt()).isNull();
        assertThat(sdJwt.presentationWithoutKbJwt()).isEqualTo(issuer + "~");
    }

    @Test
    void exactlyMaxDisclosuresIsAccepted() {
        String raw = "a.b.c~" + "WyJzIiwgMV0~".repeat(MAX_DISCLOSURES);
        assertThat(parse(raw).disclosures()).hasSize(MAX_DISCLOSURES);
    }

    @Test
    void disclosuresListIsImmutable() {
        SdJwt sdJwt = parse(vector("rfc9901-5.2-sd-jwt-kb.txt"));
        assertThatThrownBy(() -> sdJwt.disclosures().add("x")).isInstanceOf(UnsupportedOperationException.class);
    }

    // ---------------------------------------------------------------- negative

    @Test
    void moreThanMaxDisclosuresIsLimitExceeded() {
        String raw = "a.b.c~" + "WyJzIiwgMV0~".repeat(MAX_DISCLOSURES + 1);
        assertCode(() -> parse(raw), WalletErrorCode.LIMIT_EXCEEDED);
        assertCode(() -> SdJwt.parse("a.b.c~d~e~", 1, MAX_JWT_BYTES), WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void presentationLargerThanMaxJwtBytesIsLimitExceeded() {
        String raw = vector("rfc9901-5.2-sd-jwt-kb.txt");
        assertCode(() -> SdJwt.parse(raw, MAX_DISCLOSURES, raw.length() - 1), WalletErrorCode.LIMIT_EXCEEDED);
        assertThat(SdJwt.parse(raw, MAX_DISCLOSURES, raw.length()).disclosures()).hasSize(4);
    }

    @Test
    void missingTildeIsInvalidResponse() {
        assertCode(() -> parse("a.b.c"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void nullOrEmptyOrMissingIssuerJwtIsInvalidResponse() {
        assertCode(() -> parse(null), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> parse(""), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> parse("~"), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> parse("~WyJzIiwgMV0~"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void nonAsciiOrIllegalCharactersAreInvalidResponse() {
        assertCode(() -> parse("a.b.cé~"), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> parse("a.b c~"), WalletErrorCode.INVALID_RESPONSE);
        assertCode(() -> parse("a.b.c~x.y.z!"), WalletErrorCode.INVALID_RESPONSE);
    }

    @Test
    void emptyOrMalformedDisclosureSegmentIsDisclosureInvalid() {
        assertCode(() -> parse("a.b.c~~"), WalletErrorCode.DISCLOSURE_INVALID);
        assertCode(() -> parse("a.b.c~WyJzIiwgMV0~~x.y.z"), WalletErrorCode.DISCLOSURE_INVALID);
        assertCode(() -> parse("a.b.c~Wy.Jz~"), WalletErrorCode.DISCLOSURE_INVALID);
        assertCode(() -> parse("a.b.c~WyJzIiwgMV0=~"), WalletErrorCode.DISCLOSURE_INVALID);
    }

    @Test
    void negativeOrZeroLimitsAreRejectedAsProgrammingErrors() {
        assertThatThrownBy(() -> SdJwt.parse("a.b.c~", -1, MAX_JWT_BYTES)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SdJwt.parse("a.b.c~", MAX_DISCLOSURES, 0)).isInstanceOf(IllegalArgumentException.class);
    }
}
