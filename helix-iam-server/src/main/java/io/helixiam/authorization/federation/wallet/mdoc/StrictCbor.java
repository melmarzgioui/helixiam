/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.mdoc;

import io.helixiam.common.json.JsonMappers;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.exc.StreamConstraintsException;
import tools.jackson.dataformat.cbor.CBORFactory;
import tools.jackson.dataformat.cbor.CBORParser;
import tools.jackson.dataformat.cbor.CBORReadFeature;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The one bounded CBOR reader for wallet input. It walks Jackson's {@link CBORParser} token by token and counts depth,
 * data items and bytes itself, so an attacker-supplied structure is refused before it is materialised. It never uses
 * {@code readTree}.
 *
 * <p>Output is a {@link CborValue} tree, not a Jackson {@code JsonNode}: see {@link CborValue} for why. Tags are read
 * with {@link CBORParser#getCurrentTags()} at the token they prefix. Kept: 0 (tdate) and 1004 (full-date) on text, 17
 * and 18 (tagged COSE_Mac0 / COSE_Sign1) on arrays. Tag 24 on a byte string becomes {@link CborValue.Embedded} with the
 * inner bytes (for a second bounded {@link #decode}) and the exact encoded item (the mdoc digest input).
 *
 * <p>Refused as {@link WalletErrorCode#INVALID_RESPONSE}: malformed or truncated input, trailing bytes, any other tag
 * (including those Jackson would interpret itself: bignums, decimal fractions, string references), stacked tags,
 * duplicate map keys, map keys that are not text or integer, {@code undefined}, unassigned simple values, and integers
 * outside the {@code long} range. Refused as {@link WalletErrorCode#LIMIT_EXCEEDED}: anything over {@link CborLimits}.
 * Exception messages never contain input content.
 */
public final class StrictCbor {

    private static final long TAG_TDATE = 0;
    private static final long TAG_COSE_MAC0 = 17;
    private static final long TAG_COSE_SIGN1 = 18;
    private static final long TAG_ENCODED_CBOR = 24;
    private static final long TAG_FULL_DATE = 1004;
    private static final Set<Long> ALLOWED_TAGS =
            Set.of(TAG_TDATE, TAG_COSE_MAC0, TAG_COSE_SIGN1, TAG_ENCODED_CBOR, TAG_FULL_DATE);

    private static final int MAJOR_UINT = 0;
    private static final int MAJOR_NINT = 1;
    private static final int MAJOR_TEXT = 3;
    private static final int MAJOR_TAG = 6;

    /** Undefined and simple values surface as embedded objects so they can be told apart from bytes and refused. */
    private static final CBORFactory FACTORY = CBORFactory.builder()
            .streamReadConstraints(JsonMappers.readConstraints().build())
            .enable(CBORReadFeature.READ_UNDEFINED_AS_EMBEDDED_OBJECT)
            .enable(CBORReadFeature.READ_SIMPLE_VALUE_AS_EMBEDDED_OBJECT)
            .build();

    private StrictCbor() {
    }

    /** Decodes with {@link CborLimits#DEFAULTS}. */
    public static CborValue decode(byte[] bytes) {
        return decode(bytes, CborLimits.DEFAULTS);
    }

    /**
     * Decodes exactly one CBOR data item that must fill {@code bytes} completely.
     *
     * @throws WalletVerificationException {@code LIMIT_EXCEEDED} or {@code INVALID_RESPONSE}
     */
    public static CborValue decode(byte[] bytes, CborLimits limits) {
        if (bytes == null || bytes.length == 0) {
            throw invalid("empty CBOR input");
        }
        if (bytes.length > limits.maxBytes()) {
            throw limit("CBOR input exceeds " + limits.maxBytes() + " bytes");
        }
        try (CBORParser parser = (CBORParser) FACTORY.createParser(bytes)) {
            Reader reader = new Reader(bytes, limits, parser);
            JsonToken first = parser.nextToken();
            if (first == null) {
                throw invalid("empty CBOR input");
            }
            CborValue root = reader.read(first, 0);
            if (parser.nextToken() != null) {
                throw invalid("trailing bytes after CBOR item");
            }
            return root;
        } catch (WalletVerificationException e) {
            throw e;
        } catch (StreamConstraintsException e) {
            throw limit("CBOR exceeds parser constraints");
        } catch (RuntimeException e) {
            // Jackson messages can quote input; never propagate them.
            throw invalid("malformed CBOR");
        }
    }

    private static final class Reader {
        private final byte[] input;
        private final CborLimits limits;
        private final CBORParser parser;
        private int items;

        Reader(byte[] input, CborLimits limits, CBORParser parser) {
            this.input = input;
            this.limits = limits;
            this.parser = parser;
        }

        /** Reads the item whose first token is {@code token}; {@code depth} is the number of enclosing containers. */
        CborValue read(JsonToken token, int depth) {
            countItem();
            int start = (int) parser.currentTokenLocation().getByteOffset();
            Long tag = currentTag(start);
            CborValue value = switch (token) {
                case START_ARRAY -> readArray(depth + 1);
                case START_OBJECT -> readMap(depth + 1);
                case VALUE_STRING -> new CborValue.Text(parser.getString());
                case VALUE_EMBEDDED_OBJECT -> readBytes();
                case VALUE_NUMBER_INT -> readInt();
                case VALUE_NUMBER_FLOAT -> readFloat();
                case VALUE_TRUE -> new CborValue.Bool(true);
                case VALUE_FALSE -> new CborValue.Bool(false);
                case VALUE_NULL -> CborValue.Null.INSTANCE;
                default -> throw invalid("unexpected CBOR token");
            };
            if (tag == null) {
                return value;
            }
            return applyTag(tag, value, start);
        }

        /** The single allowed tag on the current token, or {@code null}. Must be read before any child token. */
        private Long currentTag(int start) {
            CBORParser.TagList tags = parser.getCurrentTags();
            if (tags.isEmpty()) {
                // Jackson consumes bignum tags itself and clears the list; the head byte still shows a tag, so refuse
                // it here.
                if (start < input.length && majorType(input[start]) == MAJOR_TAG) {
                    throw invalid("unsupported CBOR tag");
                }
                return null;
            }
            if (tags.size() > 1) {
                throw invalid("stacked CBOR tags");
            }
            long tag = Integer.toUnsignedLong(tags.getFirstTag());
            if (!ALLOWED_TAGS.contains(tag)) {
                throw invalid("unsupported CBOR tag");
            }
            return tag;
        }

        private CborValue applyTag(long tag, CborValue value, int start) {
            if (tag == TAG_ENCODED_CBOR) {
                if (!(value instanceof CborValue.Bytes bytes)) {
                    throw invalid("tag 24 must wrap a byte string");
                }
                int end = (int) parser.currentLocation().getByteOffset();
                return new CborValue.Embedded(bytes.value(), Arrays.copyOfRange(input, start, end));
            }
            if (tag == TAG_TDATE || tag == TAG_FULL_DATE) {
                if (!(value instanceof CborValue.Text)) {
                    throw invalid("date tag must wrap a text string");
                }
            } else if (!(value instanceof CborValue.Array)) {
                throw invalid("COSE tag must wrap an array");
            }
            return new CborValue.Tagged(tag, value);
        }

        private CborValue readArray(int depth) {
            checkDepth(depth);
            List<CborValue> items = new ArrayList<>();
            while (true) {
                JsonToken token = parser.nextToken();
                if (token == JsonToken.END_ARRAY) {
                    return new CborValue.Array(items);
                }
                if (token == null) {
                    throw invalid("truncated CBOR array");
                }
                items.add(read(token, depth));
            }
        }

        private CborValue readMap(int depth) {
            checkDepth(depth);
            Map<CborValue, CborValue> entries = new LinkedHashMap<>();
            while (true) {
                JsonToken token = parser.nextToken();
                if (token == JsonToken.END_OBJECT) {
                    return new CborValue.Dict(entries);
                }
                if (token != JsonToken.PROPERTY_NAME) {
                    throw invalid("truncated CBOR map");
                }
                countItem();
                CborValue key = readKey();
                JsonToken valueToken = parser.nextToken();
                if (valueToken == null) {
                    throw invalid("truncated CBOR map");
                }
                if (entries.put(key, read(valueToken, depth)) != null) {
                    throw invalid("duplicate CBOR map key");
                }
            }
        }

        /**
         * Jackson renders every key as a String, so the key's major type is taken from its head byte: text stays
         * text, integers stay integers ({@code 33} and {@code "33"} are different keys). Tagged keys and byte-string
         * keys are refused.
         */
        private CborValue readKey() {
            int offset = (int) parser.currentTokenLocation().getByteOffset();
            int major = majorType(input[offset]);
            String name = parser.currentName();
            if (major == MAJOR_TEXT) {
                return new CborValue.Text(name);
            }
            if (major == MAJOR_UINT || major == MAJOR_NINT) {
                long key = Long.parseLong(name);
                // a uint64 key above Long.MAX_VALUE wraps negative in Jackson; refuse instead of misreading it
                if ((major == MAJOR_UINT) != (key >= 0)) {
                    throw invalid("CBOR integer key out of range");
                }
                return new CborValue.Int(key);
            }
            throw invalid("CBOR map key must be text or integer");
        }

        private CborValue readBytes() {
            Object embedded = parser.getEmbeddedObject();
            if (embedded instanceof byte[] bytes) {
                return new CborValue.Bytes(bytes);
            }
            throw invalid("unsupported CBOR simple value");
        }

        private CborValue readInt() {
            if (parser.getNumberType() == JsonParser.NumberType.BIG_INTEGER) {
                throw invalid("CBOR integer out of range");
            }
            return new CborValue.Int(parser.getLongValue());
        }

        private CborValue readFloat() {
            if (parser.getNumberType() == JsonParser.NumberType.BIG_DECIMAL) {
                throw invalid("unsupported CBOR decimal");
            }
            return new CborValue.Real(parser.getDoubleValue());
        }

        private void countItem() {
            if (++items > limits.maxItems()) {
                throw limit("CBOR exceeds " + limits.maxItems() + " items");
            }
        }

        private void checkDepth(int depth) {
            if (depth > limits.maxDepth()) {
                throw limit("CBOR exceeds depth " + limits.maxDepth());
            }
        }

        private static int majorType(byte head) {
            return (head & 0xff) >>> 5;
        }
    }

    private static WalletVerificationException invalid(String detail) {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, detail);
    }

    private static WalletVerificationException limit(String detail) {
        return new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED, detail);
    }
}
