/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.sdjwt;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A compact SD-JWT presentation split into its parts (RFC 9901 §4): {@code <iss-jwt>~<d1>~…~<dN>~<kb-jwt>}, where an
 * absent KB-JWT leaves an empty final component. Segments are kept byte-exact so {@link #presentationWithoutKbJwt()} is
 * the {@code sd_hash} input. Nothing here verifies a signature.
 *
 * @param issuerJwt     the Issuer-signed JWT (compact JWS)
 * @param disclosures   the disclosures in presentation order, exactly as sent
 * @param keyBindingJwt the KB-JWT, or {@code null} when the presentation ends in {@code ~}
 */
public record SdJwt(String issuerJwt, List<String> disclosures, String keyBindingJwt) {

    /** Compact JWS: three non-empty base64url segments, as both the issuer JWT and the KB-JWT must be. */
    private static final Pattern COMPACT_JWS = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

    public SdJwt {
        Objects.requireNonNull(issuerJwt, "issuerJwt");
        disclosures = List.copyOf(disclosures);
    }

    /**
     * Splits {@code "<iss-jwt>~<d1>~…~<kb-jwt>"}; an empty final component means no KB-JWT ({@code null}).
     *
     * @param maxDisclosures at most this many disclosures, else {@code LIMIT_EXCEEDED}
     * @param maxJwtBytes    the whole presentation (issuer JWT, disclosures and KB-JWT) is at most this many bytes,
     *                       else {@code LIMIT_EXCEEDED}
     */
    public static SdJwt parse(String presentation, int maxDisclosures, int maxJwtBytes) {
        if (maxDisclosures < 0 || maxJwtBytes <= 0) {
            throw new IllegalArgumentException("limits must be positive");
        }
        if (presentation == null || presentation.isEmpty()) {
            throw invalidResponse("SD-JWT presentation is empty");
        }
        if (presentation.length() > maxJwtBytes) { // accepted input is ASCII-only, so chars == bytes
            throw new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED,
                    "SD-JWT presentation exceeds " + maxJwtBytes + " bytes");
        }
        int tildes = 0;
        for (int i = 0; i < presentation.length(); i++) {
            if (presentation.charAt(i) == '~') {
                tildes++;
            }
        }
        if (tildes == 0) {
            throw invalidResponse("SD-JWT presentation has no '~' separator");
        }
        if (tildes - 1 > maxDisclosures) {
            throw new WalletVerificationException(WalletErrorCode.LIMIT_EXCEEDED,
                    "SD-JWT presentation exceeds " + maxDisclosures + " disclosures");
        }
        String[] parts = presentation.split("~", -1);
        String issuer = parts[0];
        if (!COMPACT_JWS.matcher(issuer).matches()) {
            throw invalidResponse("Issuer-signed JWT is not a compact JWS");
        }
        List<String> disclosures = new ArrayList<>(parts.length - 2);
        for (int i = 1; i < parts.length - 1; i++) {
            if (!Disclosure.BASE64URL.matcher(parts[i]).matches()) {
                throw new WalletVerificationException(WalletErrorCode.DISCLOSURE_INVALID,
                        "disclosure is empty or not unpadded base64url");
            }
            disclosures.add(parts[i]);
        }
        String kb = parts[parts.length - 1];
        if (kb.isEmpty()) {
            kb = null;
        } else if (!COMPACT_JWS.matcher(kb).matches()) {
            throw invalidResponse("Key Binding JWT is not a compact JWS");
        }
        return new SdJwt(issuer, disclosures, kb);
    }

    /**
     * The exact ASCII string whose hash is {@code sd_hash}: everything up to and including the last '~' before the
     * KB-JWT ({@code <iss-jwt>~<d1>~…~<dN>~}, RFC 9901 §4.3.1).
     */
    public String presentationWithoutKbJwt() {
        StringBuilder sb = new StringBuilder(issuerJwt).append('~');
        for (String d : disclosures) {
            sb.append(d).append('~');
        }
        return sb.toString();
    }

    /**
     * The expected KB-JWT {@code sd_hash}: base64url(hash(ASCII({@link #presentationWithoutKbJwt()}))) with the
     * SD-JWT's {@code _sd_alg}. Pass {@link SdJwtDisclosures#sdAlgOf} of the verified issuer payload, never a constant.
     */
    public String sdHash(String sdAlg) {
        return SdJwtDisclosures.digest(presentationWithoutKbJwt(), sdAlg);
    }

    /** Redacted: disclosures carry PID values and must never reach a log line. */
    @Override
    public String toString() {
        return "SdJwt[disclosures=" + disclosures.size() + ", kbJwt=" + (keyBindingJwt != null) + "]";
    }

    private static WalletVerificationException invalidResponse(String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.INVALID_RESPONSE, safeDetail);
    }
}
