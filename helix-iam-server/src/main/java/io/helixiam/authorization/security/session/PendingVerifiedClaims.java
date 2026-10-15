/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.session;

import io.helixiam.common.json.JsonMappers;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Verify-only wallet step (security review item 1): the {@code verified_claims} a succeeded step released, pinned to
 * the authorization request the login is completing — its {@code client_id} and a hash of its {@code client_id},
 * {@code state}, {@code nonce} and {@code redirect_uri} — with an expiry ({@link #TTL_SECONDS}). It waits in the
 * session ({@link AuthTimeStamper#VERIFIED_CLAIMS_SESSION_ATTRIBUTE}); {@link SsoSessionBindingAuthorizationService}
 * binds it only to the code of that very request, and drops it on any other code, after the TTL, or when an
 * authorization is removed in the browser (consent denied). Pure.
 */
public final class PendingVerifiedClaims {

    /** How long a released step's claims wait for their code. */
    public static final long TTL_SECONDS = 300;
    private static final ObjectMapper JSON = JsonMappers.plain();

    private PendingVerifiedClaims() {
    }

    /** SHA-256 (hex) of the length-prefixed request parameters; a missing one counts as empty. */
    public static String requestHash(final String clientId, final String state, final String nonce,
                                     final String redirectUri) {
        final StringBuilder in = new StringBuilder("helix-verified-claims-v1;");
        for (final String v : new String[] {clientId, state, nonce, redirectUri}) {
            final String value = v == null ? "" : v;
            in.append(value.length()).append(':').append(value).append(';');
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(in.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** The pending value: {@code verifiedClaimsJson} pinned to {@code clientId} and {@code requestHash} until {@code expiresAt}. */
    public static String wrap(final String verifiedClaimsJson, final String clientId, final String requestHash,
                              final Instant expiresAt) {
        try {
            final ObjectNode node = JSON.createObjectNode();
            node.put("client_id", clientId);
            node.put("request", requestHash);
            node.put("expires", expiresAt.getEpochSecond());
            node.set("verified_claims", JSON.readTree(verifiedClaimsJson));
            return JSON.writeValueAsString(node);
        } catch (final JacksonException e) {
            throw new IllegalArgumentException("verified_claims is not JSON", e);
        }
    }

    /** The {@code verified_claims} JSON when {@code pending} is for exactly this client and request and not expired. */
    public static Optional<String> claimsFor(final String pending, final String clientId, final String requestHash,
                                             final Instant now) {
        if (pending == null || clientId == null || requestHash == null) {
            return Optional.empty();
        }
        try {
            final JsonNode node = JSON.readTree(pending);
            if (node == null || !node.path("verified_claims").isObject()
                    || !MessageDigest.isEqual(clientId.getBytes(StandardCharsets.UTF_8),
                            node.path("client_id").asString("").getBytes(StandardCharsets.UTF_8))
                    || !MessageDigest.isEqual(requestHash.getBytes(StandardCharsets.UTF_8),
                            node.path("request").asString("").getBytes(StandardCharsets.UTF_8))
                    || !node.path("expires").canConvertToLong()
                    || now.getEpochSecond() >= node.path("expires").asLong()) {
                return Optional.empty();
            }
            return Optional.of(JSON.writeValueAsString(node.get("verified_claims")));
        } catch (final JacksonException e) {
            return Optional.empty();
        }
    }
}
