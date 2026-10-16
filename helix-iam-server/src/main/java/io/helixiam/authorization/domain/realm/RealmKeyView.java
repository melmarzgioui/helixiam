/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.domain.realm;

import io.helixiam.authorization.service.key.RealmKeyMaterial;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Helix IAM B8: a safe, admin-facing projection of a {@link RealmKey} for the Realm Keys console.
 *
 * <p>Deliberately carries only <b>public</b> material — ids, algorithm, lifecycle status, the Base64 public key, the
 * public facts of its certificate and the timestamps (epoch millis). The encrypted private key is NEVER mapped here,
 * so it cannot leak across the admin API.
 *
 * @param kid                  the JWK {@code kid} tokens carry ({@code null} if the stored key cannot be read)
 * @param source               GENERATED, IMPORTED or CSR
 * @param hasCsr               whether a CSR can be downloaded again ({@code GET /keys/{keyId}/csr})
 * @param publicKeyFingerprint SHA-256 of the public key (SPKI)
 * @param certificate          the leaf certificate's facts, or {@code null} when the key has no certificate
 * @param activatableAt        for a PENDING key: when the minimum staging time has passed (epoch millis)
 */
public record RealmKeyView(String keyId, String algorithm, String status, String publicKey,
                           Long createdAt, Long rotatedAt, String kid, String source, Long activatedAt,
                           boolean hasCsr, String publicKeyFingerprint, CertificateInfo certificate,
                           Long activatableAt) {

    /** Days before notAfter from which a certificate counts as expiring (console chip, expiry warnings). */
    public static final long EXPIRY_WARNING_DAYS = 30;

    /**
     * @param expiry OK, EXPIRING (within {@value #EXPIRY_WARNING_DAYS} days) or EXPIRED
     */
    public record CertificateInfo(String subject, String issuer, String serialNumber, Long notBefore, Long notAfter,
                                  String sha256Fingerprint, boolean selfSigned, int chainLength, String expiry) {
    }

    /** Maps a stored key to its public projection (drops the private key). */
    public static RealmKeyView from(final RealmKey key) {
        return from(key, Instant.now(), Duration.ZERO);
    }

    public static RealmKeyView from(final RealmKey key, final Instant now, final Duration minStaging) {
        String kid = null;
        String fingerprint = null;
        try {
            final PublicKey pub = RealmKeyMaterial.decodePublic(key.getJwsAlgorithm(), key.getPublicKey());
            kid = RealmKeyMaterial.kid(pub);
            fingerprint = RealmKeyMaterial.publicKeyFingerprint(pub);
        } catch (final RuntimeException e) {
            // an unreadable stored key is still listed (so it can be retired)
        }
        return new RealmKeyView(
                key.getKeyId(), key.getJwsAlgorithm(), key.getStatus(), key.getPublicKey(),
                millis(key.getCreationDate()), millis(key.getRotatedDate()), kid, key.getSource(),
                millis(key.getActivatedDate()), key.getCsrPem() != null && !key.getCsrPem().isBlank(), fingerprint,
                certificate(key.getCertificateChainPem(), now),
                key.hasStatus(RealmKey.Status.PENDING) && key.getCreationDate() != null
                        ? key.getCreationDate().getTime() + minStaging.toMillis() : null);
    }

    /** The leaf facts of a stored chain, or {@code null}. */
    public static CertificateInfo certificate(final String chainPem, final Instant now) {
        if (chainPem == null || chainPem.isBlank()) {
            return null;
        }
        try {
            final List<X509Certificate> chain = RealmKeyMaterial.parseChain(chainPem);
            final X509Certificate leaf = chain.get(0);
            return new CertificateInfo(leaf.getSubjectX500Principal().getName(), leaf.getIssuerX500Principal().getName(),
                    leaf.getSerialNumber().toString(16), leaf.getNotBefore().getTime(), leaf.getNotAfter().getTime(),
                    RealmKeyMaterial.fingerprint(leaf), RealmKeyMaterial.isSelfSigned(leaf), chain.size(),
                    expiry(leaf.getNotAfter().toInstant(), now));
        } catch (final RuntimeException e) {
            return null;
        }
    }

    /** OK, EXPIRING or EXPIRED for a certificate ending at {@code notAfter}. */
    public static String expiry(final Instant notAfter, final Instant now) {
        if (!now.isBefore(notAfter)) {
            return "EXPIRED";
        }
        return notAfter.isBefore(now.plus(Duration.ofDays(EXPIRY_WARNING_DAYS))) ? "EXPIRING" : "OK";
    }

    private static Long millis(final java.util.Date d) {
        return d == null ? null : d.getTime();
    }
}
