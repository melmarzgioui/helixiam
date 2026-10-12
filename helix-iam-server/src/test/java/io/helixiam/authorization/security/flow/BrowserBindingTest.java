/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The browser binding of a federated login (controller ruling 1): the hash of a random per-login secret kept in the
 * HTTP session, never the session id, so it survives the session id rotation of Task 2.
 */
class BrowserBindingTest {

    @Test
    void beginReturnsTheBase64urlSha256OfASecretKeptInTheSession() throws Exception {
        final MockHttpSession session = new MockHttpSession();

        final String hash = BrowserBinding.begin(session, "wallet");

        assertThat(hash).matches("[A-Za-z0-9_-]{43}");
        final String secret = (String) session.getAttribute(BrowserBinding.ATTRIBUTE_PREFIX + "wallet");
        assertThat(Base64.getUrlDecoder().decode(secret)).hasSize(16); // 128-bit secret
        assertThat(secret).isNotEqualTo(hash);
        assertThat(hash).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.US_ASCII))));
        assertThat(hash).isNotEqualTo(session.getId());
    }

    @Test
    void theBindingSurvivesSessionIdRotation() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final String hash = BrowserBinding.begin(request.getSession(), "wallet");
        final String before = request.getSession().getId();

        request.changeSessionId();

        assertThat(request.getSession().getId()).isNotEqualTo(before);
        assertThat(BrowserBinding.current(request.getSession(), "wallet")).isEqualTo(hash);
    }

    @Test
    void eachLoginGetsANewSecretAndAliasesAreSeparate() {
        final MockHttpSession session = new MockHttpSession();

        final String first = BrowserBinding.begin(session, "wallet");
        final String other = BrowserBinding.begin(session, "other");
        final String second = BrowserBinding.begin(session, "wallet");

        assertThat(second).isNotEqualTo(first);
        assertThat(BrowserBinding.current(session, "wallet")).isEqualTo(second);
        assertThat(BrowserBinding.current(session, "other")).isEqualTo(other);
    }

    @Test
    void currentIsNullWithoutABindingAndAfterClear() {
        final MockHttpSession session = new MockHttpSession();
        assertThat(BrowserBinding.current(session, "wallet")).isNull();
        assertThat(BrowserBinding.current(null, "wallet")).isNull();

        BrowserBinding.begin(session, "wallet");
        BrowserBinding.clear(session, "wallet");

        assertThat(BrowserBinding.current(session, "wallet")).isNull();
        assertThat(Collections.list(session.getAttributeNames())).isEmpty();
    }
}
