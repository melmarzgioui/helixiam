/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.mdoc.CborValue;
import io.helixiam.authorization.federation.wallet.mdoc.StrictCbor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The Status List decoding of {@link StatusListToken} (zlib inflate with a cap, bit extraction) against the
 * draft-ietf-oauth-status-list-21 vectors: the §4.1 small examples and the Appendix C 2^20-entry lists (JSON {@code lst}
 * and CBOR {@code StatusList}), every index of each list.
 */
class StatusListTokenTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void smallExamplesDecode() throws IOException {
        final JsonNode doc = vector("status-list-21-4.1-small-examples.json");
        for (final JsonNode ex : doc.get("examples")) {
            final int bits = ex.get("bits").asInt();
            final byte[] list = StatusListToken.inflate(Base64.getUrlDecoder().decode(ex.get("lst").asText()));
            assertThat(HexFormat.of().formatHex(list)).isEqualTo(ex.get("uncompressed_hex").asText());
            final JsonNode statuses = ex.get("statuses");
            for (int i = 0; i < statuses.size(); i++) {
                assertThat(StatusListToken.statusAt(list, bits, i)).as("bits=%d idx=%d", bits, i)
                        .isEqualTo(statuses.get(i).asInt());
            }
        }
    }

    @Test
    void smallExampleCborStatusListDecodes() throws IOException {
        final JsonNode ex = vector("status-list-21-4.1-small-examples.json").get("examples").get(0);
        final CborValue.Dict dict = (CborValue.Dict) StrictCbor.decode(
                HexFormat.of().parseHex(ex.get("cbor_status_list_hex").asText()));
        final byte[] lst = ((CborValue.Bytes) dict.get("lst").orElseThrow()).value();
        assertThat(((CborValue.Int) dict.get("bits").orElseThrow()).value()).isEqualTo(1);
        assertThat(HexFormat.of().formatHex(StatusListToken.inflate(lst)))
                .isEqualTo(ex.get("uncompressed_hex").asText());
    }

    @ParameterizedTest
    @ValueSource(strings = {"status-list-21-C.1-1bit.json", "status-list-21-C.2-2bit.json",
            "status-list-21-C.3-4bit.json", "status-list-21-C.4-8bit.json"})
    void appendixCListsDecodeAtEveryIndex(final String file) throws IOException {
        final JsonNode doc = vector(file);
        final int bits = doc.get("bits").asInt();
        final int size = doc.get("size").asInt();
        final JsonNode expected = doc.get("expected_nonzero");

        final byte[] fromJson = StatusListToken.inflate(Base64.getUrlDecoder().decode(doc.get("lst").asText()));
        final CborValue.Dict cbor = (CborValue.Dict) StrictCbor.decode(
                HexFormat.of().parseHex(doc.get("cbor_hex").asText()));
        final byte[] fromCbor = StatusListToken.inflate(((CborValue.Bytes) cbor.get("lst").orElseThrow()).value());
        assertThat(fromCbor).isEqualTo(fromJson);
        assertThat(fromJson.length * 8 / bits).isEqualTo(size);

        int nonZero = 0;
        for (int i = 0; i < size; i++) {
            final int status = StatusListToken.statusAt(fromJson, bits, i);
            final JsonNode want = expected.get(Integer.toString(i));
            assertThat(status).as("idx %d", i).isEqualTo(want == null ? 0 : want.asInt());
            if (status != 0) {
                nonZero++;
            }
        }
        assertThat(nonZero).isEqualTo(expected.size());
    }

    @Test
    void indexBeyondTheListIsInvalidResponse() {
        assertThatThrownBy(() -> StatusListToken.statusAt(new byte[] {0}, 1, 8))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.INVALID_RESPONSE));
        assertThatThrownBy(() -> StatusListToken.statusAt(new byte[] {0}, 1, -1))
                .isInstanceOf(WalletVerificationException.class);
    }

    @Test
    void inflateRefusesMoreThanTwoMegabytes() {
        final byte[] bomb = TokenStatusListClientTest.zlib(new byte[StatusListToken.MAX_INFLATED_BYTES + 1]);
        assertThatThrownBy(() -> StatusListToken.inflate(bomb))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.LIMIT_EXCEEDED));
        assertThat(StatusListToken.inflate(TokenStatusListClientTest.zlib(
                new byte[StatusListToken.MAX_INFLATED_BYTES]))).hasSize(StatusListToken.MAX_INFLATED_BYTES);
    }

    @Test
    @Timeout(value = 3, unit = TimeUnit.SECONDS)
    void hugeZipBombStopsEarly() {
        final byte[] bomb = zlibOfZeros(256L * 1024 * 1024); // 256 MB inflated, ~250 KB compressed
        assertThat(bomb.length).isLessThan(TokenStatusListClient.MAX_BODY_BYTES / 2);
        final long start = System.nanoTime();
        assertThatThrownBy(() -> StatusListToken.inflate(bomb))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.LIMIT_EXCEEDED));
        // stopping at 2 MB takes milliseconds; inflating 256 MB would not
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(500));
    }

    /** zlib of {@code size} zero bytes, deflated in chunks so the input is never held in memory. */
    static byte[] zlibOfZeros(final long size) {
        final Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        final byte[] chunk = new byte[1024 * 1024];
        final byte[] buf = new byte[64 * 1024];
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (long fed = 0; fed < size; fed += chunk.length) {
            deflater.setInput(chunk);
            while (!deflater.needsInput()) {
                out.write(buf, 0, deflater.deflate(buf));
            }
        }
        deflater.finish();
        while (!deflater.finished()) {
            out.write(buf, 0, deflater.deflate(buf));
        }
        deflater.end();
        return out.toByteArray();
    }

    @Test
    void inflateRefusesTruncatedAndTrailingInput() {
        final byte[] good = TokenStatusListClientTest.zlib(new byte[100]);
        final byte[] truncated = java.util.Arrays.copyOf(good, good.length - 3);
        final byte[] trailing = java.util.Arrays.copyOf(good, good.length + 2);
        for (final byte[] bad : new byte[][] {truncated, trailing, new byte[0], "plain".getBytes()}) {
            assertThatThrownBy(() -> StatusListToken.inflate(bad))
                    .isInstanceOfSatisfying(WalletVerificationException.class,
                            e -> assertThat(e.code()).isEqualTo(WalletErrorCode.INVALID_RESPONSE));
        }
    }

    private static JsonNode vector(final String name) throws IOException {
        try (InputStream in = StatusListTokenTest.class.getResourceAsStream("/wallet/vectors/status-list/" + name)) {
            assertThat(in).as(name).isNotNull();
            return JSON.readTree(in);
        }
    }
}
