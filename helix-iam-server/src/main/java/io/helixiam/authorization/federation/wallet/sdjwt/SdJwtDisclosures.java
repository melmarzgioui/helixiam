/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Selective-disclosure processing per RFC 9901 §7.1 steps 3–5 (docs/eudi-wallet-spec-notes.md §3.6). The input payload
 * must already come from a signature-verified Issuer-signed JWT; this class only rebuilds the disclosed claims.
 *
 * <p>Refused with {@code DISCLOSURE_INVALID}: a malformed disclosure, the same digest twice anywhere in the payload
 * (decoys included, directly or through disclosed values), the same disclosure sent twice, a disclosure no digest
 * references, an object-property disclosure in an array slot or an array-element disclosure in {@code _sd}, a disclosed
 * name equal to {@code _sd}, {@code ...} or a claim already present at that level, a malformed {@code _sd} /
 * {@code {"...": digest}}, a {@code ...} key outside an array element, and {@code _sd_alg} below the top level.
 * Unmatched digests are decoys: ignored in {@code _sd}, removed from arrays. {@code _sd} and {@code _sd_alg} never
 * appear in the result. Nesting deeper than {@code maxDepth} containers is {@code LIMIT_EXCEEDED}.
 *
 * <p>A digest cannot be referenced from inside its own disclosed value without a hash cycle; any repeated reference
 * (the only way a loop could arise) is caught by the "same digest twice" rule, and the depth limit bounds recursion.
 */
public final class SdJwtDisclosures {

    /** Container nesting limit for the processed payload; the same default as the CBOR reader (CborLimits). */
    public static final int DEFAULT_MAX_DEPTH = 16;
    /** The default {@code _sd_alg} when the claim is absent (RFC 9901 §4.1.1). */
    public static final String DEFAULT_SD_ALG = "sha-256";

    static final String SD = "_sd";
    static final String ELLIPSIS = "...";
    static final String SD_ALG = "_sd_alg";

    private SdJwtDisclosures() {
    }

    /** {@link #resolve(Map, List, String, int)} with {@link #DEFAULT_MAX_DEPTH}. */
    public static Map<String, Object> resolve(Map<String, Object> payload, List<String> disclosures, String sdAlg) {
        return resolve(payload, disclosures, sdAlg, DEFAULT_MAX_DEPTH);
    }

    /**
     * Resolves {@code _sd} / array {@code "..."} digests recursively and returns the fully disclosed claim object.
     *
     * @param payload     the verified Issuer-signed JWT payload (not modified)
     * @param disclosures the presented disclosures, exactly as in the presentation
     * @param sdAlg       the hash algorithm; {@code null} means "the payload's {@code _sd_alg}". When given, it must
     *                    equal {@link #sdAlgOf(Map)} of the payload, so a caller cannot pick a different hash.
     * @param maxDepth    container nesting limit (the top-level object counts as 1)
     */
    public static Map<String, Object> resolve(Map<String, Object> payload, List<String> disclosures, String sdAlg,
                                              int maxDepth) {
        if (maxDepth < 1) {
            throw new IllegalArgumentException("maxDepth must be positive");
        }
        if (payload == null || disclosures == null) {
            throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE,
                    "SD-JWT payload or disclosures missing");
        }
        String payloadAlg = sdAlgOf(payload);
        if (sdAlg != null) {
            requireAllowed(sdAlg);
            if (!sdAlg.equals(payloadAlg)) {
                throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED,
                        "_sd_alg does not match the expected algorithm");
            }
        }
        Map<String, Disclosure> byDigest = new LinkedHashMap<>();
        for (String encoded : disclosures) {
            Disclosure d = Disclosure.decode(encoded, payloadAlg);
            if (byDigest.putIfAbsent(d.digest(), d) != null) {
                throw Disclosure.invalid("the same disclosure was presented more than once");
            }
        }
        Resolver resolver = new Resolver(byDigest, maxDepth);
        Map<String, Object> result = resolver.object(payload, 1, true);
        if (resolver.used.size() != byDigest.size()) {
            throw Disclosure.invalid("a disclosure is not referenced by any digest");
        }
        return result;
    }

    /**
     * The payload's hash algorithm: top-level {@code _sd_alg}, or {@code sha-256} when absent (RFC 9901 §4.1.1). Use it
     * for the disclosure digests <em>and</em> for the KB-JWT {@code sd_hash} ({@link SdJwt#sdHash(String)}).
     */
    public static String sdAlgOf(Map<String, Object> payload) {
        if (payload == null || !payload.containsKey(SD_ALG)) {
            return DEFAULT_SD_ALG;
        }
        if (!(payload.get(SD_ALG) instanceof String alg)) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "_sd_alg is not a string");
        }
        requireAllowed(alg);
        return alg;
    }

    /** True when {@code sdAlg} is in the allow-list ({@code sha-256}, {@code sha-384}, {@code sha-512}). */
    public static boolean isAllowed(String sdAlg) {
        return jcaName(sdAlg) != null;
    }

    /**
     * base64url(hash(ASCII(input))) with the SD-JWT hash algorithm {@code sdAlg}. Used for disclosure digests (RFC 9901
     * §4.2.3) and, over {@link SdJwt#presentationWithoutKbJwt()}, for {@code sd_hash} (§4.3.1).
     */
    static String digest(final String input, final String sdAlg) {
        final String jca = requireAllowed(sdAlg);
        for (int i = 0; i < input.length(); i++) {
            if (input.charAt(i) > 0x7F) { // US-ASCII encoding would silently turn it into '?'
                throw new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, "digest input is not ASCII");
            }
        }
        try {
            final byte[] h = java.security.MessageDigest.getInstance(jca)
                    .digest(input.getBytes(StandardCharsets.US_ASCII));
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String requireAllowed(String sdAlg) {
        String jca = jcaName(sdAlg);
        if (jca == null) {
            throw new WalletVerificationException(WalletErrorCode.ALGORITHM_NOT_ALLOWED, "_sd_alg");
        }
        return jca;
    }

    private static String jcaName(String sdAlg) {
        if (sdAlg == null) {
            return null;
        }
        return switch (sdAlg) {
            case "sha-256" -> "SHA-256";
            case "sha-384" -> "SHA-384";
            case "sha-512" -> "SHA-512";
            default -> null;
        };
    }

    /** One resolution pass: tracks every digest seen and every disclosure used. */
    private static final class Resolver {
        private final Map<String, Disclosure> byDigest;
        private final int maxDepth;
        private final Set<String> seen = new HashSet<>();
        private final Set<String> used = new HashSet<>();

        Resolver(Map<String, Disclosure> byDigest, int maxDepth) {
            this.byDigest = byDigest;
            this.maxDepth = maxDepth;
        }

        Map<String, Object> object(Map<?, ?> in, int depth, boolean topLevel) {
            checkDepth(depth);
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : in.entrySet()) {
                if (!(e.getKey() instanceof String key)) {
                    throw Disclosure.invalid("claim name is not a string");
                }
                switch (key) {
                    case SD -> { } // handled below, once the plain claims at this level are known
                    case ELLIPSIS -> throw Disclosure.invalid("'...' is only allowed in an array element");
                    case SD_ALG -> {
                        if (!topLevel) {
                            throw Disclosure.invalid("_sd_alg is only allowed at the top level");
                        }
                    }
                    default -> out.put(key, value(e.getValue(), depth));
                }
            }
            if (in.containsKey(SD)) {
                if (!(in.get(SD) instanceof List<?> digests)) {
                    throw Disclosure.invalid("_sd is not an array");
                }
                for (Object digest : digests) {
                    Disclosure d = lookup(digest);
                    if (d == null) {
                        continue; // decoy, or a disclosure the holder did not present
                    }
                    if (d.isArrayElement()) {
                        throw Disclosure.invalid("array-element disclosure referenced from _sd");
                    }
                    if (out.containsKey(d.claimName())) {
                        throw Disclosure.invalid("disclosed claim already exists at this level");
                    }
                    out.put(d.claimName(), value(d.value(), depth));
                }
            }
            return out;
        }

        List<Object> array(List<?> in, int depth) {
            checkDepth(depth);
            List<Object> out = new ArrayList<>(in.size());
            for (Object element : in) {
                if (element instanceof Map<?, ?> m && m.containsKey(ELLIPSIS)) {
                    if (m.size() != 1) {
                        throw Disclosure.invalid("array digest object has other keys");
                    }
                    Disclosure d = lookup(m.get(ELLIPSIS));
                    if (d == null) {
                        continue; // decoy, or not presented: the element is removed
                    }
                    if (!d.isArrayElement()) {
                        throw Disclosure.invalid("object-property disclosure referenced from an array");
                    }
                    out.add(value(d.value(), depth));
                } else {
                    out.add(value(element, depth));
                }
            }
            return out;
        }

        private Object value(Object v, int depth) {
            if (v instanceof Map<?, ?> m) {
                return object(m, depth + 1, false);
            }
            if (v instanceof List<?> l) {
                return array(l, depth + 1);
            }
            return v;
        }

        /** Records the digest (rejecting a repeat) and returns its disclosure, or null for a decoy. */
        private Disclosure lookup(Object digest) {
            if (!(digest instanceof String s)) {
                throw Disclosure.invalid("digest is not a string");
            }
            if (!seen.add(s)) {
                throw Disclosure.invalid("the same digest appears more than once");
            }
            Disclosure d = byDigest.get(s);
            if (d != null) {
                used.add(s);
            }
            return d;
        }

        private void checkDepth(int depth) {
            if (depth > maxDepth) {
                throw new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED,
                        "SD-JWT payload exceeds depth " + maxDepth);
            }
        }
    }
}
