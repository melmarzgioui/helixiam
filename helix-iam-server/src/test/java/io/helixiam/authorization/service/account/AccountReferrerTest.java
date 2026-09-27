/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.account;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** B1: the account console's return link is only ever an address on one of the client's registered redirect origins. */
class AccountReferrerTest {

    private static final List<String> REDIRECTS = List.of("https://app.monthfold.example/auth/callback",
            "http://127.0.0.1:43127/auth/callback");

    @Test
    void anAddressOnARedirectOrigin_isAccepted() {
        assertThat(AccountReferrer.allowed("https://app.monthfold.example/settings?tab=profile", REDIRECTS)).isTrue();
        assertThat(AccountReferrer.allowed("https://APP.monthfold.example:443/", REDIRECTS)).as("default port, case").isTrue();
        assertThat(AccountReferrer.allowed("http://127.0.0.1:43127/home", REDIRECTS)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://evil.example/settings",
            "https://app.monthfold.example.evil.example/",
            "https://app.monthfold.example:8443/",
            "http://app.monthfold.example/",
            "http://127.0.0.1:43128/home",
            "javascript:alert(1)",
            "JaVaScRiPt://app.monthfold.example/%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//app.monthfold.example/settings",
            "/realms/acme/account",
            "https://user:pass@app.monthfold.example/",
            "https://app.monthfold.example\\@evil.example/",
            "not a uri",
            ""})
    void anyOtherAddress_isRefused(final String uri) {
        assertThat(AccountReferrer.allowed(uri, REDIRECTS)).isFalse();
    }

    @Test
    void nothingIsAllowed_forAClientWithoutRedirectUris_orWithoutAnAddress() {
        assertThat(AccountReferrer.allowed("https://app.monthfold.example/", List.of())).isFalse();
        assertThat(AccountReferrer.allowed(null, REDIRECTS)).isFalse();
        assertThat(AccountReferrer.allowed("https://app.monthfold.example/" + "a".repeat(3000), REDIRECTS)).isFalse();
    }

    @Test
    void theLabel_isTheClientName_neverItsInternalId() {
        assertThat(AccountReferrer.label("Monthfold web", "web", "5b0f6c1e-0000-4000-8000-000000000001")).isEqualTo("Monthfold web");
        assertThat(AccountReferrer.label("5b0f6c1e-0000-4000-8000-000000000001", "web", "5b0f6c1e-0000-4000-8000-000000000001"))
                .isEqualTo("web");
        assertThat(AccountReferrer.label(" ", "web", "id")).isEqualTo("web");
    }
}
