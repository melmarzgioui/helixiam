/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.fapi;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

/**
 * Helix IAM B11 (FAPI / RFC 8705 — OAuth 2.0 Mutual-TLS): computes the {@code x5t#S256} certificate
 * confirmation thumbprint — the base64url-encoded (no padding) SHA-256 hash over the DER encoding of an
 * X.509 client certificate — and parses a forwarded PEM certificate. This is the value placed in the
 * access token's {@code cnf} claim so a resource server can verify the presented client certificate
 * matches the one the token was bound to (proof-of-possession), exactly as the DPoP {@code cnf.jkt}
 * binds to a key thumbprint. Pure + side-effect-free so it is unit-testable without a TLS handshake.
 */
public final class CertificateThumbprint {

    private static final Logger LOG = LogManager.getLogger(CertificateThumbprint.class);

    private CertificateThumbprint() {
    }

    /** The RFC 8705 {@code x5t#S256} value for the certificate: base64url(no-pad)( SHA-256( DER ) ). */
    public static String x5tS256(final X509Certificate certificate) {
        try {
            final byte[] der = certificate.getEncoded();
            final byte[] digest = MessageDigest.getInstance("SHA-256").digest(der);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (final Exception e) {
            // A certificate that can't be DER-encoded or hashed can't be bound; surface no thumbprint.
            throw new IllegalArgumentException("Cannot compute x5t#S256 for certificate", e);
        }
    }

    /**
     * Parses a forwarded client certificate. Accepts a PEM block as-is or URL-encoded (the common shape
     * when a reverse proxy forwards {@code ssl_client_escaped_cert} in a header). Returns empty for
     * blank/garbage input so a missing/bad cert simply yields no binding rather than an error.
     */
    public static Optional<X509Certificate> parsePem(final String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        String pem = raw.trim();
        // Reverse proxies often URL-encode the PEM (newlines → %0A). Decode if it looks encoded.
        if (pem.contains("%")) {
            try {
                pem = URLDecoder.decode(pem, StandardCharsets.UTF_8).trim();
            } catch (final IllegalArgumentException ignored) {
                // not actually url-encoded — fall through with the raw value
            }
        }
        if (!pem.contains("BEGIN CERTIFICATE")) {
            return Optional.empty();
        }
        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final X509Certificate cert = (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
            return Optional.ofNullable(cert);
        } catch (final CertificateException e) {
            LOG.debug("Forwarded client certificate could not be parsed, ignoring: {}", e.getMessage());
            return Optional.empty();
        }
    }
}
