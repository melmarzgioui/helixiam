/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

/**
 * Pluggable source of signing-key material (Helix IAM E1.4).
 *
 * <p>The default {@link SoftwareRsaKeyProvider} generates RSA-2048 and EC P-256 keys in the JVM. A future HSM/KMS
 * provider (PKCS#11, cloud KMS) implements this same interface so keys are generated and held in hardware — swappable
 * by config without touching the key service.
 */
public interface SigningKeyProvider {

    /** Provider id, e.g. {@code software}, {@code pkcs11}, {@code kms}. */
    String type();

    /** Generates a fresh RS256 signing keypair. */
    GeneratedKey generate();

    /** Generates a fresh signing keypair for {@code algorithm} (RS256 or ES256). */
    default GeneratedKey generate(final String algorithm) {
        if (RealmKeyMaterial.RS256.equals(RealmKeyMaterial.requireSupportedAlgorithm(algorithm))) {
            return generate();
        }
        throw new UnsupportedOperationException("This key provider only generates RS256 keys");
    }

    /**
     * Freshly generated key material.
     *
     * @param kid              unique key id
     * @param algorithm        JWS algorithm (RS256 or ES256; {@code RSA} from older providers means RS256)
     * @param publicKeyBase64  Base64 X.509/SPKI-encoded public key
     * @param privateKeyBase64 Base64 PKCS#8-encoded private key (encrypted at rest by the store)
     */
    record GeneratedKey(String kid, String algorithm, String publicKeyBase64, String privateKeyBase64) {
        @Override
        public String toString() {
            return "GeneratedKey[" + kid + ", " + algorithm + "]"; // never key material
        }
    }
}
