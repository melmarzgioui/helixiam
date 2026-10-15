/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link StrictCbor} is the only way wallet code turns attacker-supplied bytes into a CBOR tree. It must bound depth,
 * item count and size before anything is materialised, keep the tags mdoc needs (24, 0, 1004), and refuse anything
 * ambiguous.
 *
 * <p>No ISO 18013-5 DeviceResponse vector is in {@code src/test/resources/wallet/vectors} (the ISO text is paywalled,
 * see SOURCES.md), so the "valid DeviceResponse" case is a structurally faithful one built here with Jackson's
 * {@link CBORGenerator}, following docs/eudi-wallet-spec-notes.md §6.1/§6.2.
 */
class StrictCborTest {

    private static final CBORFactory FACTORY = new CBORFactory();
    private static final HexFormat HEX = HexFormat.of();

    // ---------------------------------------------------------------- valid DeviceResponse

    @Test
    void decodesAValidDeviceResponseKeepingTagsAndIntegerKeys() throws IOException {
        byte[] item = issuerSignedItem();
        byte[] response = deviceResponse(item);

        CborValue root = StrictCbor.decode(response, CborLimits.DEFAULTS);

        CborValue.Dict top = (CborValue.Dict) root;
        assertThat(top.get("version")).contains(new CborValue.Text("1.0"));
        assertThat(top.get("status")).contains(new CborValue.Int(0));
        CborValue.Dict doc = (CborValue.Dict) ((CborValue.Array) top.get("documents").orElseThrow()).items().get(0);
        assertThat(doc.get("docType")).contains(new CborValue.Text("eu.europa.ec.eudi.pid.1"));

        CborValue.Dict issuerSigned = (CborValue.Dict) doc.get("issuerSigned").orElseThrow();
        CborValue.Dict nameSpaces = (CborValue.Dict) issuerSigned.get("nameSpaces").orElseThrow();
        CborValue.Array items = (CborValue.Array) nameSpaces.get("eu.europa.ec.eudi.pid.1").orElseThrow();
        CborValue.Embedded embedded = (CborValue.Embedded) items.items().get(0);
        assertThat(embedded.content()).isEqualTo(item);

        // COSE_Sign1 unprotected header uses integer labels (33 = x5chain); they must stay integers.
        CborValue.Array issuerAuth = (CborValue.Array) issuerSigned.get("issuerAuth").orElseThrow();
        assertThat(issuerAuth.items()).hasSize(4);
        CborValue.Dict unprotectedHeader = (CborValue.Dict) issuerAuth.items().get(1);
        assertThat(unprotectedHeader.get(33)).contains(new CborValue.Bytes(new byte[] {1, 2, 3}));
        assertThat(unprotectedHeader.get("33")).isEmpty();
        assertThat(unprotectedHeader.entries().keySet()).containsExactly(new CborValue.Int(33));
    }

    // ---------------------------------------------------------------- limits

    @Test
    void depthSixteenIsAccepted() {
        assertThat(StrictCbor.decode(nestedArrays(16), CborLimits.DEFAULTS)).isInstanceOf(CborValue.Array.class);
    }

    @Test
    void depthSeventeenIsLimitExceeded() {
        assertLimitExceeded(nestedArrays(17));
    }

    @Test
    void nestedMapsCountTowardsDepth() {
        // 17 nested single-entry maps {"a": {"a": ... 0}}
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int i = 0; i < 17; i++) {
            out.write(0xa1);
            out.write(0x61);
            out.write('a');
        }
        out.write(0x00);
        assertLimitExceeded(out.toByteArray());
    }

    @Test
    void tenThousandItemsAreAccepted() {
        // array header + 9 999 elements = 10 000 data items
        assertThat(StrictCbor.decode(flatArray(9_999), CborLimits.DEFAULTS)).isInstanceOf(CborValue.Array.class);
    }

    @Test
    void moreThanTenThousandItemsIsLimitExceeded() {
        assertLimitExceeded(flatArray(10_000));
    }

    @Test
    void mapKeysCountAsItems() {
        // map of 5 000 entries = 1 + 5 000 keys + 5 000 values = 10 001 items
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xb9);
        out.write(5_000 >> 8);
        out.write(5_000 & 0xff);
        for (int i = 0; i < 5_000; i++) {
            out.write(0x19); // uint16 key
            out.write(i >> 8);
            out.write(i & 0xff);
            out.write(0x00);
        }
        assertLimitExceeded(out.toByteArray());
    }

    @Test
    void declaredHugeArrayWithoutContentFailsWithoutAllocating() {
        // array claiming 2^32-1 elements, followed by nothing
        assertThatThrownBy(() -> StrictCbor.decode(HEX.parseHex("9affffffff"), CborLimits.DEFAULTS))
                .isInstanceOf(WalletVerificationException.class);
    }

    @Test
    void inputOverTwoHundredFiftySixKibIsLimitExceeded() {
        byte[] big = new byte[256 * 1024 + 1];
        big[0] = 0x5a; // bstr with 32-bit length
        int len = big.length - 5;
        big[1] = (byte) (len >>> 24);
        big[2] = (byte) (len >>> 16);
        big[3] = (byte) (len >>> 8);
        big[4] = (byte) len;
        assertLimitExceeded(big);
    }

    @Test
    void inputOfExactlyTwoHundredFiftySixKibIsAccepted() {
        byte[] big = new byte[256 * 1024];
        big[0] = 0x5a;
        int len = big.length - 5;
        big[1] = (byte) (len >>> 24);
        big[2] = (byte) (len >>> 16);
        big[3] = (byte) (len >>> 8);
        big[4] = (byte) len;
        assertThat(StrictCbor.decode(big, CborLimits.DEFAULTS)).isInstanceOf(CborValue.Bytes.class);
    }

    @Test
    void customLimitsAreHonoured() {
        CborLimits tight = new CborLimits(2, 100, 1_000);
        assertThat(StrictCbor.decode(nestedArrays(2), tight)).isInstanceOf(CborValue.Array.class);
        assertThatThrownBy(() -> StrictCbor.decode(nestedArrays(3), tight))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.LIMIT_EXCEEDED);
    }

    @Test
    void defaultsMatchTheConstraints() {
        assertThat(CborLimits.DEFAULTS).isEqualTo(new CborLimits(16, 10_000, 256 * 1024));
        assertThatThrownBy(() -> new CborLimits(0, 1, 1)).isInstanceOf(IllegalArgumentException.class);
    }

    // ---------------------------------------------------------------- tags

    @Test
    void tag24IsSurfacedAsBytesForASecondBoundedDecode() throws IOException {
        byte[] inner = issuerSignedItem();
        byte[] tagged = taggedBytes(24, inner);

        CborValue.Embedded embedded = (CborValue.Embedded) StrictCbor.decode(tagged, CborLimits.DEFAULTS);

        assertThat(embedded.content()).isEqualTo(inner);
        // the digest input for mdoc is the whole tag-24 item exactly as received
        assertThat(embedded.encoded()).isEqualTo(tagged);
        CborValue.Dict item = (CborValue.Dict) StrictCbor.decode(embedded.content(), CborLimits.DEFAULTS);
        assertThat(item.get("elementIdentifier")).contains(new CborValue.Text("birth_date"));
    }

    @Test
    void tag24EncodedBytesAreSlicedExactlyEvenInsideAContainer() throws IOException {
        byte[] inner = issuerSignedItem();
        byte[] tagged = taggedBytes(24, inner);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x83); // [1, 24(<<item>>), 2]
        out.write(0x01);
        out.writeBytes(tagged);
        out.write(0x02);

        CborValue.Array array = (CborValue.Array) StrictCbor.decode(out.toByteArray(), CborLimits.DEFAULTS);

        assertThat(((CborValue.Embedded) array.items().get(1)).encoded()).isEqualTo(tagged);
    }

    @Test
    void secondDecodeOfEmbeddedContentIsBoundedToo() {
        byte[] deep = nestedArrays(17);
        byte[] tagged = taggedBytes(24, deep);
        CborValue.Embedded embedded = (CborValue.Embedded) StrictCbor.decode(tagged, CborLimits.DEFAULTS);
        assertLimitExceeded(embedded.content());
    }

    @Test
    void tag24OnANonByteStringIsInvalid() {
        // 24("x")
        assertInvalid(HEX.parseHex("d8186178"));
    }

    @Test
    void fullDateTag1004IsPreserved() {
        // 1004("1990-01-01")
        CborValue value = StrictCbor.decode(HEX.parseHex("d903ec6a313939302d30312d3031"), CborLimits.DEFAULTS);
        assertThat(value).isEqualTo(new CborValue.Tagged(1004, new CborValue.Text("1990-01-01")));
    }

    @Test
    void tdateTag0IsPreserved() {
        // 0("2024-01-01T00:00:00Z")
        CborValue value = StrictCbor.decode(HEX.parseHex("c074323032342d30312d30315430303a30303a30305a"),
                CborLimits.DEFAULTS);
        assertThat(value).isEqualTo(new CborValue.Tagged(0, new CborValue.Text("2024-01-01T00:00:00Z")));
    }

    @Test
    void coseSign1TagIsPreserved() {
        // 18([h'', {}, null, h''])
        CborValue value = StrictCbor.decode(HEX.parseHex("d28440a0f640"), CborLimits.DEFAULTS);
        assertThat(value).isInstanceOf(CborValue.Tagged.class);
        assertThat(((CborValue.Tagged) value).tag()).isEqualTo(18);
    }

    @Test
    void unknownTagsAreRejected() {
        // 32("http://x") (URI tag) is not part of the mdoc profile
        assertInvalid(HEX.parseHex("d82068687474703a2f2f78"));
    }

    @Test
    void stringrefNamespaceTagIsRejected() {
        // 256([]) — Jackson would otherwise silently resolve string references
        assertInvalid(HEX.parseHex("d9010080"));
    }

    @Test
    void bignumIsRejected() {
        // 2(h'01')
        assertInvalid(HEX.parseHex("c24101"));
    }

    @Test
    void stackedTagsAreRejected() {
        // 0(1004("1990-01-01"))
        assertInvalid(HEX.parseHex("c0d903ec6a313939302d30312d3031"));
    }

    // ---------------------------------------------------------------- indefinite length (ISO 18013-5 requires definite)

    @Test
    void indefiniteLengthByteStringIsRejected() {
        // 0x5f = byte string, additional info 31 (indefinite), 0xff = break; an empty indefinite byte string.
        assertInvalid(HEX.parseHex("5fff"));
    }

    @Test
    void indefiniteLengthTextStringIsRejected() {
        // 0x7f = text string, additional info 31 (indefinite), 0xff = break; an empty indefinite text string.
        assertInvalid(HEX.parseHex("7fff"));
    }

    @Test
    void indefiniteLengthArrayIsRejected() {
        // 0x9f = array, additional info 31 (indefinite), 0xff = break; an empty indefinite array.
        assertInvalid(HEX.parseHex("9fff"));
    }

    @Test
    void indefiniteLengthMapIsRejected() {
        // 0xbf = map, additional info 31 (indefinite), 0xff = break; an empty indefinite map.
        assertInvalid(HEX.parseHex("bfff"));
    }

    @Test
    void indefiniteLengthArrayNestedInATagIsStillRejected() {
        // 18(_ 1, 2) — a COSE_Sign1 tag wrapping an indefinite-length array; the tag bytes must not hide it.
        assertInvalid(HEX.parseHex("d29f0102ff"));
    }

    @Test
    void indefiniteLengthTextMapKeyIsRejected() {
        // {_"a": 1} — an indefinite-length text string used as a map key.
        assertInvalid(HEX.parseHex("a17f6161ff01"));
    }

    @Test
    void indefiniteLengthNestingBombIsRejectedImmediately_notJustAtTheDepthLimit() {
        // 0x9f repeated never closes; it is now refused as invalid at the very first indefinite array, which is
        // both correct per ISO 18013-5 and cheaper than before (no longer needs to walk to the depth limit).
        byte[] bomb = new byte[100_000];
        Arrays.fill(bomb, (byte) 0x9f);
        assertInvalid(bomb);
    }

    // ---------------------------------------------------------------- strictness

    @Test
    void duplicateMapKeysAreRejected() {
        // {"a": 1, "a": 2}
        assertInvalid(HEX.parseHex("a2616101616102"));
    }

    @Test
    void duplicateIntegerMapKeysAreRejected() {
        // {1: 1, 1: 2}
        assertInvalid(HEX.parseHex("a201010102"));
    }

    @Test
    void textAndIntegerKeysWithTheSameDigitsAreDistinct() {
        // {1: 1, "1": 2}
        CborValue.Dict dict = (CborValue.Dict) StrictCbor.decode(HEX.parseHex("a20101613102"), CborLimits.DEFAULTS);
        assertThat(dict.get(1)).contains(new CborValue.Int(1));
        assertThat(dict.get("1")).contains(new CborValue.Int(2));
    }

    @Test
    void byteStringMapKeysAreRejected() {
        // {h'61': 1}
        assertInvalid(HEX.parseHex("a1416101"));
    }

    @Test
    void trailingBytesAreRejected() {
        assertInvalid(HEX.parseHex("0001"));
    }

    @Test
    void truncatedInputIsRejected() {
        // array of 2 with only one element
        assertInvalid(HEX.parseHex("8201"));
    }

    @Test
    void emptyInputIsRejected() {
        assertInvalid(new byte[0]);
    }

    @Test
    void undefinedIsRejected() {
        assertInvalid(HEX.parseHex("f7"));
    }

    @Test
    void unassignedSimpleValuesAreRejected() {
        assertInvalid(HEX.parseHex("f0"));
    }

    @Test
    void integerOutsideLongRangeIsRejected() {
        // uint64 max
        assertInvalid(HEX.parseHex("1bffffffffffffffff"));
    }

    @Test
    void scalarsDecode() {
        CborValue.Array array = (CborValue.Array) StrictCbor.decode(
                HEX.parseHex("8720f5f4f6fb3ff8000000000000" + "6161" + "4101"), CborLimits.DEFAULTS);
        assertThat(array.items()).containsExactly(new CborValue.Int(-1), new CborValue.Bool(true),
                new CborValue.Bool(false), CborValue.Null.INSTANCE, new CborValue.Real(1.5),
                new CborValue.Text("a"), new CborValue.Bytes(new byte[] {1}));
    }

    @Test
    void nullInputIsInvalid() {
        assertThatThrownBy(() -> StrictCbor.decode(null, CborLimits.DEFAULTS))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    // ---------------------------------------------------------------- helpers

    private static void assertLimitExceeded(byte[] bytes) {
        assertThatThrownBy(() -> StrictCbor.decode(bytes, CborLimits.DEFAULTS))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.LIMIT_EXCEEDED);
    }

    private static void assertInvalid(byte[] bytes) {
        assertThatThrownBy(() -> StrictCbor.decode(bytes, CborLimits.DEFAULTS))
                .isInstanceOf(WalletVerificationException.class)
                .extracting(e -> ((WalletVerificationException) e).code())
                .isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    private static byte[] nestedArrays(int depth) {
        byte[] bytes = new byte[depth + 1];
        Arrays.fill(bytes, 0, depth, (byte) 0x81); // array of one element
        bytes[depth] = 0x00;
        return bytes;
    }

    private static byte[] flatArray(int elements) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x99); // array, uint16 length
        out.write(elements >> 8);
        out.write(elements & 0xff);
        for (int i = 0; i < elements; i++) {
            out.write(0x00);
        }
        return out.toByteArray();
    }

    /** tag(n) wrapping a definite-length byte string, using preferred (shortest) encodings. */
    private static byte[] taggedBytes(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (tag < 24) {
            out.write(0xc0 | tag);
        } else {
            out.write(0xd8);
            out.write(tag);
        }
        int len = content.length;
        if (len < 24) {
            out.write(0x40 | len);
        } else if (len < 256) {
            out.write(0x58);
            out.write(len);
        } else {
            out.write(0x59);
            out.write(len >> 8);
            out.write(len & 0xff);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] issuerSignedItem() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator g = (CBORGenerator) FACTORY.createGenerator(out)) {
            g.writeStartObject(null, 4); // digestID, random, elementIdentifier, elementValue
            g.writeNumberField("digestID", 0);
            g.writeBinaryField("random", new byte[16]);
            g.writeStringField("elementIdentifier", "birth_date");
            g.writeFieldName("elementValue");
            g.writeTag(1004);
            g.writeString("1990-01-01");
            g.writeEndObject();
        }
        return out.toByteArray();
    }

    /** Definite-length throughout (ISO 18013-5): every {@code writeStartObject}/{@code writeStartArray} is sized. */
    private static byte[] deviceResponse(byte[] issuerSignedItem) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (CBORGenerator g = (CBORGenerator) FACTORY.createGenerator(out)) {
            g.writeStartObject(null, 3); // version, documents, status
            g.writeStringField("version", "1.0");
            g.writeFieldName("documents");
            g.writeStartArray(null, 1);
            g.writeStartObject(null, 3); // docType, issuerSigned, deviceSigned
            g.writeStringField("docType", "eu.europa.ec.eudi.pid.1");
            g.writeFieldName("issuerSigned");
            g.writeStartObject(null, 2); // nameSpaces, issuerAuth
            g.writeFieldName("nameSpaces");
            g.writeStartObject(null, 1); // "eu.europa.ec.eudi.pid.1"
            g.writeFieldName("eu.europa.ec.eudi.pid.1");
            g.writeStartArray(null, 1);
            g.writeTag(24);
            g.writeBinary(issuerSignedItem);
            g.writeEndArray();
            g.writeEndObject();
            g.writeFieldName("issuerAuth"); // COSE_Sign1 [protected, unprotected, payload, signature]
            g.writeStartArray(null, 4);
            g.writeBinary(HEX.parseHex("a10126")); // {1: -7}
            g.writeStartObject(null, 1); // 33: x5chain
            g.writeFieldId(33); // x5chain
            g.writeBinary(new byte[] {1, 2, 3});
            g.writeEndObject();
            g.writeBinary(taggedBytes(24, HEX.parseHex("a0")));
            g.writeBinary(new byte[64]);
            g.writeEndArray();
            g.writeEndObject();
            g.writeFieldName("deviceSigned");
            g.writeStartObject(null, 2); // nameSpaces, deviceAuth
            g.writeFieldName("nameSpaces");
            g.writeTag(24);
            g.writeBinary(HEX.parseHex("a0"));
            g.writeFieldName("deviceAuth");
            g.writeStartObject(null, 1); // deviceSignature
            g.writeFieldName("deviceSignature");
            g.writeStartArray(null, 4);
            g.writeBinary(HEX.parseHex("a10126"));
            g.writeStartObject(null, 0); // empty unprotected header
            g.writeEndObject();
            g.writeNull();
            g.writeBinary(new byte[64]);
            g.writeEndArray();
            g.writeEndObject();
            g.writeEndObject();
            g.writeEndObject();
            g.writeEndArray();
            g.writeNumberField("status", 0);
            g.writeEndObject();
        }
        return out.toByteArray();
    }
}
