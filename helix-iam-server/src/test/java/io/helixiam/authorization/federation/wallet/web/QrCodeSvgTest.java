/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.e2e.WalletE2eFixture;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Task 18: the wallet page's QR code is rendered on the server as SVG (no script, no CDN): black modules on a white
 * ground with a quiet zone, whatever the realm's theme, and it decodes back to the exact invocation URL.
 */
class QrCodeSvgTest {

    private static final String URL = "haip-vp://?client_id=x509_hash%3AabcDEF_-123&request_uri="
            + "https%3A%2F%2Fhelix.example%2Frealms%2Facme%2Foid4vp%2Feudi-wallet%2Frequest%2F"
            + "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5d2FsZG8";

    @Test
    void theSvgDecodesToTheExactUrl() {
        assertThat(WalletE2eFixture.decodeQrSvg(QrCodeSvg.svg(URL))).isEqualTo(URL);
    }

    @Test
    void darkModulesOnALightGround_noScriptNoStyle() {
        final String svg = QrCodeSvg.svg(URL);

        assertThat(svg).startsWith("<svg xmlns=\"http://www.w3.org/2000/svg\"")
                .contains("<rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>")
                .contains("fill=\"#000000\"")
                .contains("shape-rendering=\"crispEdges\"")
                .doesNotContain("<script").doesNotContain("style=").doesNotContain("href");
    }

    @Test
    void theDataUriIsBase64Svg() {
        final String uri = QrCodeSvg.dataUri(URL);

        assertThat(uri).startsWith("data:image/svg+xml;base64,");
        assertThat(new String(Base64.getDecoder().decode(uri.substring(uri.indexOf(',') + 1)),
                StandardCharsets.UTF_8)).isEqualTo(QrCodeSvg.svg(URL));
    }

    @Test
    void refusesNothingToEncode() {
        assertThatThrownBy(() -> QrCodeSvg.svg("")).isInstanceOf(IllegalArgumentException.class);
    }
}
