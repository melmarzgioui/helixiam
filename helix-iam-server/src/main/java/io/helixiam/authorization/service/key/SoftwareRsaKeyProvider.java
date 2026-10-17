/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;

/**
 * Default {@link SigningKeyProvider}: generates RSA-2048 (RS256) and EC P-256 (ES256) keys in the JVM.
 *
 * <p>The private key is returned Base64-encoded and is encrypted at rest by the key store. For hardware-backed keys,
 * replace this with a PKCS#11/KMS provider implementing the same interface — the key service is unaffected.
 */
@Component
public class SoftwareRsaKeyProvider implements SigningKeyProvider {

    @Override
    public String type() {
        return "software";
    }

    @Override
    public GeneratedKey generate() {
        return generate(RealmKeyMaterial.RS256);
    }

    @Override
    public GeneratedKey generate(final String algorithm) {
        final String alg = RealmKeyMaterial.requireSupportedAlgorithm(algorithm);
        final KeyPair keyPair = RealmKeyMaterial.generate(alg);
        return new GeneratedKey(UUID.randomUUID().toString(), alg,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }
}
