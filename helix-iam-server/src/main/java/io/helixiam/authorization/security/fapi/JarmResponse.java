/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import com.nimbusds.jwt.JWTClaimsSet;

import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * Helix IAM B11 (FAPI / JARM — JWT Secured Authorization Response Mode, openid-financial-api-jarm): the
 * pure core of JARM. The authorization endpoint normally returns its response parameters ({@code code},
 * {@code state}, {@code iss}, or {@code error}/{@code error_description}) as plain query/fragment/form
 * values; with a {@code .jwt} response mode they are instead packed into a single signed {@code response}
 * JWT carrying {@code iss}/{@code aud}/{@code exp}. This class resolves the delivery (base) mode and builds
 * that claim set; signing with the realm key and the redirect itself are thin glue in the filter.
 */
public final class JarmResponse {

    private JarmResponse() {
    }

    /** True when the response mode is one of the JWT-secured variants (jwt / query.jwt / fragment.jwt / form_post.jwt). */
    public static boolean isJarm(final String responseMode) {
        return responseMode != null && (responseMode.equals("jwt") || responseMode.endsWith(".jwt"));
    }

    /**
     * The underlying delivery mode for a JARM response mode. Bare {@code jwt} defaults to {@code query}
     * (the JARM default for an authorization-code response); the prefixed variants name their base mode.
     */
    public static String baseMode(final String responseMode) {
        if (responseMode == null || responseMode.equals("jwt")) {
            return "query";
        }
        final int dot = responseMode.indexOf(".jwt");
        return dot > 0 ? responseMode.substring(0, dot) : "query";
    }

    /**
     * Builds the JARM response JWT claim set: {@code iss} (the realm issuer), {@code aud} (the client_id),
     * {@code exp} (issuedAt + ttl), plus every authorization response parameter as a top-level claim.
     */
    public static JWTClaimsSet claims(final String issuer, final String clientId, final Map<String, String> params,
                                      final Instant issuedAt, final long ttlSeconds) {
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(clientId)
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(issuedAt.plusSeconds(ttlSeconds)));
        if (params != null) {
            params.forEach((k, v) -> {
                if (k != null && v != null) {
                    builder.claim(k, v);
                }
            });
        }
        return builder.build();
    }
}
