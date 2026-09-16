/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.device;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Helix IAM E4.1: the "none" (self / trust-on-first-use) attestation verifier — the dev default
 * used when platform attestation isn't enforced. It still requires a bound server nonce and a
 * parseable P-256 device key, so enrollment can't be replayed or store junk. Apple App Attest and
 * Android Key Attestation verifiers drop in later as additional {@link AttestationVerifier} beans.
 */
class SelfAttestationVerifierTest {

    private final SelfAttestationVerifier verifier = new SelfAttestationVerifier();

    private static byte[] p256Spki() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair().getPublic().getEncoded();
    }

    @Test
    void platformIsNone() {
        assertThat(verifier.platform()).isEqualTo("none");
    }

    @Test
    void acceptsAParseableKeyWithABoundNonce() throws Exception {
        final byte[] nonce = "server-nonce".getBytes(StandardCharsets.UTF_8);
        assertThat(verifier.verify(new byte[0], nonce, p256Spki())).isTrue();
    }

    @Test
    void rejectsAMissingNonce() throws Exception {
        assertThat(verifier.verify(new byte[0], new byte[0], p256Spki())).isFalse();
    }

    @Test
    void rejectsAnUnparseableDeviceKey() {
        assertThat(verifier.verify(new byte[0], "n".getBytes(StandardCharsets.UTF_8), new byte[]{1, 2, 3})).isFalse();
    }
}
