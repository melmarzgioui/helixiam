/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.amqp.key;

/**
 * Helix IAM B8: publisher-side copy of the subscriber's {@code RealmKeyView} (two-copy DTO, same field order).
 * Carries only public signing-key material for the admin Realm Keys console — never the private key.
 */
public record RealmKeyView(String keyId, String algorithm, String status, String publicKey,
                           Long createdAt, Long rotatedAt, String kid, String source, Long activatedAt,
                           boolean hasCsr, String publicKeyFingerprint, CertificateInfo certificate) {

    /** The leaf certificate's public facts. */
    public record CertificateInfo(String subject, String issuer, String serialNumber, Long notBefore, Long notAfter,
                                  String sha256Fingerprint, boolean selfSigned, int chainLength, String expiry) {
    }

    /** The fingerprint the audit detail names: the certificate's, else the public key's. */
    public String fingerprint() {
        return certificate != null ? certificate.sha256Fingerprint() : publicKeyFingerprint;
    }
}
