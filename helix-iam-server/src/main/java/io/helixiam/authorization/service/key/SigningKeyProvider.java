/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

/**
 * Pluggable source of signing-key material (Helix IAM E1.4).
 *
 * <p>The default {@link SoftwareRsaKeyProvider} generates RSA keys in the JVM. A future
 * HSM/KMS provider (PKCS#11, cloud KMS) implements this same interface so keys are
 * generated and held in hardware — swappable by config without touching the key service.
 */
public interface SigningKeyProvider {

    /** Provider id, e.g. {@code software}, {@code pkcs11}, {@code kms}. */
    String type();

    /** Generates a fresh signing keypair. */
    GeneratedKey generate();

    /**
     * Freshly generated key material.
     *
     * @param kid              unique key id
     * @param algorithm        key algorithm (e.g. {@code RSA})
     * @param publicKeyBase64  Base64 X.509/SPKI-encoded public key
     * @param privateKeyBase64 Base64 PKCS#8-encoded private key (encrypted at rest by the store)
     */
    record GeneratedKey(String kid, String algorithm, String publicKeyBase64, String privateKeyBase64) {
    }
}
