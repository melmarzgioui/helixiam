/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The key-certificate match proof signs with the full SHA-2 ECDSA algorithm of the key's curve (CodeQL
 * {@code java/potentially-weak-cryptographic-algorithm}: the name is a constant, never assembled from a "SHA" prefix).
 */
class SoftwareRealmSigningKeysSignatureAlgorithmTest {

    @Test
    void eachEsAlgorithm_mapsToItsSha2Ecdsa() {
        assertThat(SoftwareRealmSigningKeys.signatureAlgorithm(JWSAlgorithm.ES256)).isEqualTo("SHA256withECDSA");
        assertThat(SoftwareRealmSigningKeys.signatureAlgorithm(JWSAlgorithm.ES384)).isEqualTo("SHA384withECDSA");
        assertThat(SoftwareRealmSigningKeys.signatureAlgorithm(JWSAlgorithm.ES512)).isEqualTo("SHA512withECDSA");
    }

    @Test
    void anyOtherAlgorithm_isRefused() {
        assertThatThrownBy(() -> SoftwareRealmSigningKeys.signatureAlgorithm(JWSAlgorithm.RS256))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SoftwareRealmSigningKeys.signatureAlgorithm(JWSAlgorithm.ES256K))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
