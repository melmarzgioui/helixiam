/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.e2e.WalletE2eFixture;
import org.junit.jupiter.api.RepeatedTest;

import java.security.SecureRandom;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fix round 2: every invocation-URL-shaped QR code decodes (the e2e suites scan them). Random request ids give a
 * different matrix each time, so this runs many shapes.
 */
class QrCodeSvgDecodeTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @RepeatedTest(200)
    void randomInvocationUrls_alwaysDecode() {
        final byte[] id = new byte[32];
        RANDOM.nextBytes(id);
        final String url = "haip-vp://?client_id=x509_hash%3A" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(id) + "&request_uri=http%3A%2F%2Flocalhost%3A54321%2Frealms%2Fwallet-1a2b3c4d%2F"
                + "oid4vp%2Feudi-5e6f7a8b%2Frequest%2F" + Base64.getUrlEncoder().withoutPadding().encodeToString(id);

        assertThat(WalletE2eFixture.decodeQrSvg(QrCodeSvg.svg(url))).isEqualTo(url);
    }
}
