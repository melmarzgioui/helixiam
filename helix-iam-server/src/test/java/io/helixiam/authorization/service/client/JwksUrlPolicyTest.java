/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.client;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link JwksUrlPolicy#code} must classify the same way {@link JwksUrlPolicy#problem} does — the console maps the
 * code onto its own translated copy instead of matching the (English-only) message text.
 */
class JwksUrlPolicyTest {

    @Test
    void blankIsAcceptable() {
        assertThat(JwksUrlPolicy.problem(null, false)).isNull();
        assertThat(JwksUrlPolicy.problem("", false)).isNull();
        assertThat(JwksUrlPolicy.problem("   ", false)).isNull();
        assertThat(JwksUrlPolicy.code(null, false)).isNull();
        assertThat(JwksUrlPolicy.code("", false)).isNull();
    }

    @Test
    void anHttpsUrlWithAHostIsAcceptable() {
        assertThat(JwksUrlPolicy.problem("https://app.example/.well-known/jwks.json", false)).isNull();
        assertThat(JwksUrlPolicy.code("https://app.example/.well-known/jwks.json", false)).isNull();
    }

    @Test
    void unparseableTextIsNotAUrl() {
        assertThat(JwksUrlPolicy.problem("not a url", false)).isEqualTo(JwksUrlPolicy.NOT_A_URL);
        assertThat(JwksUrlPolicy.code("not a url", false)).isEqualTo(JwksUrlPolicy.CODE_NOT_A_URL);
    }

    @Test
    void httpIsRefusedOutsideDev() {
        assertThat(JwksUrlPolicy.problem("http://localhost:8094/jwks", false)).isEqualTo(JwksUrlPolicy.NOT_HTTPS);
        assertThat(JwksUrlPolicy.code("http://localhost:8094/jwks", false)).isEqualTo(JwksUrlPolicy.CODE_NOT_HTTPS);
    }

    @Test
    void httpToLocalhostIsAcceptedUnderDev() {
        assertThat(JwksUrlPolicy.problem("http://localhost:8094/jwks", true)).isNull();
        assertThat(JwksUrlPolicy.problem("http://127.0.0.1:8094/jwks", true)).isNull();
        assertThat(JwksUrlPolicy.code("http://localhost:8094/jwks", true)).isNull();
    }

    @Test
    void httpToARealHostIsRefusedEvenUnderDev() {
        assertThat(JwksUrlPolicy.problem("http://app.example/jwks", true)).isEqualTo(JwksUrlPolicy.NOT_HTTPS);
        assertThat(JwksUrlPolicy.code("http://app.example/jwks", true)).isEqualTo(JwksUrlPolicy.CODE_NOT_HTTPS);
    }
}
