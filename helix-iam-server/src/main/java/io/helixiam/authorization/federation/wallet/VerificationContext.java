/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.status.StatusPolicy;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;

import java.util.List;

/**
 * Everything a {@link PresentationVerifier} checks a presentation against, fixed per transaction.
 *
 * <p>{@code acceptedVcts} is a set because national PIDs carry their own {@code vct} (e.g. {@code urn:eudi:pid:de:1},
 * spec notes §PID); a credential is accepted when its {@code vct} or one of its {@code aka_vcts} is in the set.
 * {@code allowLegacyVcSdJwtTyp} (default {@code false}) additionally accepts the pre-rename {@code vc+sd-jwt} JOSE
 * {@code typ}.
 *
 * <p>{@code dcApiOrigins} is empty for the redirect / {@code direct_post} flows. For a response that came through the W3C
 * Digital Credentials API (OpenID4VP 1.0 Appendix A) it holds the verifier's own expected origins (from configuration,
 * never from the request): the presentation must then be bound to one of them instead of the {@code client_id}
 * (SD-JWT KB-JWT {@code aud = "origin:" + origin}, Appendix A.4; mdoc DeviceAuth over the
 * {@code OpenID4VPDCAPIHandover} SessionTranscript of that origin, Appendix B.2.6.2), and {@code responseUri} is not
 * used.
 */
public record VerificationContext(String clientId, String nonce, String responseUri, byte[] encryptionJwkThumbprint,
        java.time.Instant now, java.time.Duration clockSkew, TrustAnchors anchors, StatusPolicy statusPolicy,
        java.util.Set<String> acceptedVcts, String acceptedDoctype, boolean allowLegacyVcSdJwtTyp,
        List<String> dcApiOrigins) {

    /** OpenID4VP 1.0 Appendix A.4: the audience prefix of a DC API presentation. */
    public static final String ORIGIN_PREFIX = "origin:";

    public VerificationContext {
        dcApiOrigins = dcApiOrigins == null ? List.of() : List.copyOf(dcApiOrigins);
    }

    /** A redirect / {@code direct_post} context (no DC API origins). */
    public VerificationContext(final String clientId, final String nonce, final String responseUri,
            final byte[] encryptionJwkThumbprint, final java.time.Instant now, final java.time.Duration clockSkew,
            final TrustAnchors anchors, final StatusPolicy statusPolicy, final java.util.Set<String> acceptedVcts,
            final String acceptedDoctype, final boolean allowLegacyVcSdJwtTyp) {
        this(clientId, nonce, responseUri, encryptionJwkThumbprint, now, clockSkew, anchors, statusPolicy,
                acceptedVcts, acceptedDoctype, allowLegacyVcSdJwtTyp, List.of());
    }

    /**
     * This context for a response received through the Digital Credentials API, bound to one of {@code origins}.
     *
     * @throws IllegalArgumentException when {@code origins} is empty, or an entry is blank or carries the
     *                                  {@code origin:} prefix (the bare origin is expected)
     */
    public VerificationContext forDcApi(final List<String> origins) {
        if (origins == null || origins.isEmpty()) {
            throw new IllegalArgumentException("A DC API response needs at least one expected origin");
        }
        for (final String origin : origins) {
            if (origin == null || origin.isBlank() || origin.startsWith(ORIGIN_PREFIX)) {
                throw new IllegalArgumentException("Expected origins are bare origins such as https://host");
            }
        }
        return new VerificationContext(clientId, nonce, responseUri, encryptionJwkThumbprint, now, clockSkew, anchors,
                statusPolicy, acceptedVcts, acceptedDoctype, allowLegacyVcSdJwtTyp, origins);
    }

    /** Whether the response came through the Digital Credentials API. */
    public boolean dcApi() {
        return !dcApiOrigins.isEmpty();
    }

    /**
     * Whether {@code aud} is an audience this response may carry: the {@code client_id} in the redirect flows, or
     * {@code "origin:" + o} for an expected origin {@code o} over the DC API (exact string match).
     */
    public boolean acceptsAudience(final String aud) {
        if (aud == null) {
            return false;
        }
        if (!dcApi()) {
            return aud.equals(clientId);
        }
        return aud.startsWith(ORIGIN_PREFIX) && dcApiOrigins.contains(aud.substring(ORIGIN_PREFIX.length()));
    }
}
