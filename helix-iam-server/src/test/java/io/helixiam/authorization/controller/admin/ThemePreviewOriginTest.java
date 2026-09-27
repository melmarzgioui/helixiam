/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Task 3 review M6: the preview names the configured public origin, not whatever Host the request carried. */
class ThemePreviewOriginTest {

    @Test
    void theConfiguredBaseUrlWins_reducedToItsOrigin() {
        assertThat(ThemePreviewController.origin("https://id.example.com/some/path/", "http://10.0.0.7:8080"))
                .isEqualTo("https://id.example.com");
        assertThat(ThemePreviewController.origin("https://id.example.com:8443", "http://evil.example"))
                .isEqualTo("https://id.example.com:8443");
    }

    @Test
    void withoutAUsableConfiguredUrl_theRequestOriginIsUsed() {
        assertThat(ThemePreviewController.origin("", "http://localhost:8080")).isEqualTo("http://localhost:8080");
        assertThat(ThemePreviewController.origin(null, "http://localhost:8080")).isEqualTo("http://localhost:8080");
        assertThat(ThemePreviewController.origin("not a url", "http://localhost:8080")).isEqualTo("http://localhost:8080");
    }
}
