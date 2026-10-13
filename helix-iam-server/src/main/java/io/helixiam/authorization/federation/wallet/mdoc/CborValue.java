/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * An immutable CBOR data item as produced by {@link StrictCbor}.
 *
 * <p>Why not Jackson's {@code JsonNode}: a JSON tree has no place for CBOR tags (mdoc needs tag 24, tag 0 and tag
 * 1004), it turns integer map keys (COSE header labels, MSO digest IDs) into strings so {@code 33} and {@code "33"}
 * become indistinguishable, and it cannot keep the exact encoded bytes of a tag-24 item, which are the mdoc digest
 * input. This small tree keeps all three.
 */
public sealed interface CborValue {

    /** Text string (major type 3). */
    record Text(String value) implements CborValue {
        public Text {
            Objects.requireNonNull(value);
        }
    }

    /** Byte string (major type 2). Defensively copied. */
    record Bytes(byte[] value) implements CborValue {
        public Bytes {
            value = value.clone();
        }

        @Override
        public byte[] value() {
            return value.clone();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Bytes other && Arrays.equals(value, other.value);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(value);
        }

        @Override
        public String toString() {
            return "Bytes[" + value.length + " bytes]";
        }
    }

    /** Integer (major types 0 and 1) within the range of {@code long}. */
    record Int(long value) implements CborValue {}

    /** Floating-point number (half, single or double precision). */
    record Real(double value) implements CborValue {}

    /** {@code true} or {@code false}. */
    record Bool(boolean value) implements CborValue {}

    /** CBOR {@code null}. */
    enum Null implements CborValue { INSTANCE }

    /** Array (major type 4), definite or indefinite length. */
    record Array(List<CborValue> items) implements CborValue {
        public Array {
            items = List.copyOf(items);
        }
    }

    /**
     * Map (major type 5). Keys are {@link Text} or {@link Int} only, unique, in encounter order.
     */
    record Dict(Map<CborValue, CborValue> entries) implements CborValue {
        public Dict {
            entries = Collections.unmodifiableMap(new LinkedHashMap<>(entries));
        }

        public Optional<CborValue> get(String key) {
            return Optional.ofNullable(entries.get(new Text(key)));
        }

        public Optional<CborValue> get(long key) {
            return Optional.ofNullable(entries.get(new Int(key)));
        }
    }

    /**
     * A tagged item for the tags StrictCbor keeps as-is: 0 (tdate), 1004 (full-date), 17 (COSE_Mac0_Tagged) and 18
     * (COSE_Sign1_Tagged).
     */
    record Tagged(long tag, CborValue content) implements CborValue {
        public Tagged {
            Objects.requireNonNull(content);
        }
    }

    /**
     * Tag 24 (encoded CBOR data item). Not decoded: the caller runs a second, separately bounded
     * {@link StrictCbor#decode} over {@link #content()}.
     *
     * @param content the bytes inside the byte string, i.e. the embedded CBOR
     * @param encoded the whole tag-24 item exactly as received (tag header, byte-string header and content); this is
     *                the mdoc digest input and must never be re-encoded
     */
    record Embedded(byte[] content, byte[] encoded) implements CborValue {
        public Embedded {
            content = content.clone();
            encoded = encoded.clone();
        }

        @Override
        public byte[] content() {
            return content.clone();
        }

        @Override
        public byte[] encoded() {
            return encoded.clone();
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Embedded other && Arrays.equals(encoded, other.encoded);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(encoded);
        }

        @Override
        public String toString() {
            return "Embedded[" + content.length + " bytes, head " + HexFormat.of().formatHex(encoded, 0,
                    Math.min(4, encoded.length)) + "]";
        }
    }
}
