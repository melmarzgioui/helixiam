/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/**
 * One decoded SD-JWT Disclosure (RFC 9901 §4.2.1, §4.2.2): {@code [salt, name, value]} for an object property or
 * {@code [salt, value]} for an array element. Anything else is refused.
 *
 * @param encoded   the disclosure exactly as presented (the digest input)
 * @param digest    base64url(hash(ASCII(encoded))) under the SD-JWT's {@code _sd_alg}
 * @param claimName the claim name for an object-property disclosure, {@code null} for an array element
 * @param value     the disclosed value (String, Boolean, Long, Double, BigInteger, List, Map or null)
 */
public record Disclosure(String encoded, String digest, String claimName, Object value) {

    /** Unpadded base64url, the only encoding RFC 9901 allows. */
    static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

    /** Disclosure JSON: duplicate members refused, ints as Long (like Nimbus), nothing after the array, shallow. */
    private static final ObjectMapper JSON = JsonMapper.builder(com.fasterxml.jackson.core.JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64).build())
                    .build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.USE_LONG_FOR_INTS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    /** Redacted: a disclosure carries PID values and must never reach a log line. */
    @Override
    public String toString() {
        return "Disclosure[digest=" + digest + (claimName == null ? ", array element]" : ", claim]");
    }

    /** True for {@code [salt, value]} (array element), false for {@code [salt, name, value]}. */
    public boolean isArrayElement() {
        return claimName == null;
    }

    /** Decodes and structurally validates one disclosure; every failure is {@code DISCLOSURE_INVALID}. */
    static Disclosure decode(String encoded, String sdAlg) {
        if (encoded == null || !BASE64URL.matcher(encoded).matches()) {
            throw invalid("disclosure is not unpadded base64url");
        }
        final String json;
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(encoded);
            json = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (IllegalArgumentException | CharacterCodingException e) {
            throw invalid("disclosure is not base64url-encoded UTF-8");
        }
        final Object parsed;
        try {
            parsed = JSON.readValue(json, Object.class);
        } catch (java.io.IOException e) {
            throw invalid("disclosure is not valid JSON");
        }
        if (!(parsed instanceof List<?> array) || array.isEmpty() || !(array.get(0) instanceof String)) {
            throw invalid("disclosure is not a JSON array starting with a string salt");
        }
        String digest = SdJwtDisclosures.digest(encoded, sdAlg);
        return switch (array.size()) {
            case 2 -> new Disclosure(encoded, digest, null, array.get(1));
            case 3 -> {
                if (!(array.get(1) instanceof String name)) {
                    throw invalid("disclosure claim name is not a string");
                }
                if (SdJwtDisclosures.SD.equals(name) || SdJwtDisclosures.ELLIPSIS.equals(name)) {
                    throw invalid("disclosure uses a reserved claim name");
                }
                yield new Disclosure(encoded, digest, name, array.get(2));
            }
            default -> throw invalid("disclosure array must have 2 or 3 elements");
        };
    }

    static WalletVerificationException invalid(String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.DISCLOSURE_INVALID, safeDetail);
    }
}
