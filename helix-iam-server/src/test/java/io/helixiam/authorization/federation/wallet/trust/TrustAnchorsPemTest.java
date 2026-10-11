/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrustAnchorsPemTest {

    private static final TestPki PKI = TestPki.create();
    private static final TestPki OTHER = TestPki.create("Other");

    @Test
    void parsesEveryAnchorAndIntermediate() {
        final TrustAnchors anchors = TrustAnchors.fromPem(PKI.rootPem() + OTHER.rootPem(), PKI.intermediatePem(),
                RevocationMode.SOFT_FAIL);

        assertThat(anchors.anchors()).extracting(TrustAnchor::getTrustedCert)
                .containsExactlyInAnyOrder(PKI.root(), OTHER.root());
        assertThat(anchors.pinnedIntermediates()).containsExactly(PKI.intermediate());
        assertThat(anchors.revocation()).isEqualTo(RevocationMode.SOFT_FAIL);
    }

    @Test
    void intermediatesAreOptional() {
        assertThat(TrustAnchors.fromPem(PKI.rootPem(), null, RevocationMode.OFF).pinnedIntermediates()).isEmpty();
        assertThat(TrustAnchors.fromPem(PKI.rootPem(), "  ", RevocationMode.OFF).pinnedIntermediates()).isEmpty();
    }

    @Test
    void zeroAnchorsIsRejected() {
        assertThatThrownBy(() -> TrustAnchors.fromPem("", null, RevocationMode.OFF))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TrustAnchors.fromPem(null, null, RevocationMode.OFF))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TrustAnchors.fromPem("no pem here", null, RevocationMode.OFF))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void malformedPemIsRejectedWithoutLibraryDetail() {
        assertThatThrownBy(() -> TrustAnchors.fromPem(
                "-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n-----END CERTIFICATE-----\n", null, RevocationMode.OFF))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The trust anchors could not be parsed as PEM certificates");
        assertThatThrownBy(() -> TrustAnchors.fromPem(PKI.rootPem(),
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", RevocationMode.OFF))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("The pinned intermediates could not be parsed as PEM certificates");
    }

    @Test
    void nonCertificatePemIsRejected() {
        final String key = "-----BEGIN PUBLIC KEY-----\n"
                + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW5zFh7SZ0hKqbOmy2mH0zvO1x3x6p7Ep6J5bE1E6y5JmYb2HC1q1QyJ7c1Zz"
                + "\nVnP2s8l7g0o4pX7mV8dQ4r1y9g==\n-----END PUBLIC KEY-----\n";
        assertThatThrownBy(() -> TrustAnchors.fromPem(key, null, RevocationMode.OFF))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void revocationModeIsRequired() {
        assertThatThrownBy(() -> TrustAnchors.fromPem(PKI.rootPem(), null, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void collectionsAreImmutable() {
        final TrustAnchors anchors = TrustAnchors.fromPem(PKI.rootPem(), PKI.intermediatePem(), RevocationMode.OFF);
        assertThatThrownBy(() -> anchors.anchors().clear()).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> anchors.pinnedIntermediates().clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
