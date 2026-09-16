/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.device;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Helix IAM E4.1: auto-discovered catalogue of {@link AttestationVerifier}s keyed by platform.
 * Spring injects every verifier bean, so a new platform (Apple App Attest, Android Key Attestation)
 * is added by dropping a {@code @Component} — no change here. Enrollment routes by platform id.
 */
@Component
public class AttestationVerifierRegistry {

    private static final Logger LOG = LogManager.getLogger(AttestationVerifierRegistry.class);

    private final Map<String, AttestationVerifier> byPlatform = new LinkedHashMap<>();

    public AttestationVerifierRegistry(final Collection<AttestationVerifier> verifiers) {
        for (final AttestationVerifier verifier : verifiers) {
            if (byPlatform.containsKey(verifier.platform())) {
                throw new IllegalArgumentException("Duplicate attestation verifier platform: " + verifier.platform());
            }
            byPlatform.put(verifier.platform(), verifier);
        }
        LOG.info("Helix attestation SPI: discovered {} verifier(s): {}", byPlatform.size(), byPlatform.keySet());
    }

    /** Routes an enrollment attestation to the verifier for the given platform. */
    public boolean verify(final String platform, final byte[] attestation, final byte[] nonce, final byte[] publicKey) {
        final AttestationVerifier verifier = byPlatform.get(platform);
        if (verifier == null) {
            throw new IllegalArgumentException("No attestation verifier for platform: " + platform);
        }
        return verifier.verify(attestation, nonce, publicKey);
    }
}
