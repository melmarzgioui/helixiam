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

        final String hash = BrowserBinding.begin(session, "acme", "wallet");

        assertThat(hash).matches("[A-Za-z0-9_-]{43}");
        final String secret = (String) session.getAttribute(BrowserBinding.sessionKey(BrowserBinding.ATTRIBUTE_PREFIX, "acme", "wallet"));
        assertThat(Base64.getUrlDecoder().decode(secret)).hasSize(16); // 128-bit secret
        assertThat(secret).isNotEqualTo(hash);
        assertThat(hash).isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.US_ASCII))));
        assertThat(hash).isNotEqualTo(session.getId());
    }

    @Test
    void theBindingSurvivesSessionIdRotation() {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        final String hash = BrowserBinding.begin(request.getSession(), "acme", "wallet");
        final String before = request.getSession().getId();

        request.changeSessionId();

        assertThat(request.getSession().getId()).isNotEqualTo(before);
        assertThat(BrowserBinding.current(request.getSession(), "acme", "wallet")).isEqualTo(hash);
    }

    @Test
    void eachLoginGetsANewSecretAndAliasesAreSeparate() {
        final MockHttpSession session = new MockHttpSession();

        final String first = BrowserBinding.begin(session, "acme", "wallet");
        final String other = BrowserBinding.begin(session, "acme", "other");
        final String second = BrowserBinding.begin(session, "acme", "wallet");

        assertThat(second).isNotEqualTo(first);
        assertThat(BrowserBinding.current(session, "acme", "wallet")).isEqualTo(second);
        assertThat(BrowserBinding.current(session, "acme", "other")).isEqualTo(other);
    }

    @Test
    void currentIsNullWithoutABindingAndAfterClear() {
        final MockHttpSession session = new MockHttpSession();
        assertThat(BrowserBinding.current(session, "acme", "wallet")).isNull();
        assertThat(BrowserBinding.current(null, "acme", "wallet")).isNull();

        BrowserBinding.begin(session, "acme", "wallet");
        BrowserBinding.clear(session, "acme", "wallet");

        assertThat(BrowserBinding.current(session, "acme", "wallet")).isNull();
        assertThat(Collections.list(session.getAttributeNames())).isEmpty();
    }

    @Test
    void theSameAliasInTwoRealms_hasTwoSeparateBindings() {
        final MockHttpSession session = new MockHttpSession();

        final String realmA = BrowserBinding.begin(session, "realm-a", "eudi-wallet");
        final String realmB = BrowserBinding.begin(session, "realm-b", "eudi-wallet");

        assertThat(BrowserBinding.current(session, "realm-a", "eudi-wallet")).isEqualTo(realmA);
        assertThat(BrowserBinding.current(session, "realm-b", "eudi-wallet")).isEqualTo(realmB);
        BrowserBinding.clear(session, "realm-a", "eudi-wallet");
        assertThat(BrowserBinding.current(session, "realm-b", "eudi-wallet")).isEqualTo(realmB);
    }

    @Test
    void noRealmAndAliasPair_spellsAnotherPairsKey() {
        assertThat(BrowserBinding.sessionKey("P_", "a:b", "c")).isNotEqualTo(BrowserBinding.sessionKey("P_", "a", "b:c"));
        assertThat(BrowserBinding.sessionKey("P_", null, "x")).isEqualTo("P_0::x");
    }
}
