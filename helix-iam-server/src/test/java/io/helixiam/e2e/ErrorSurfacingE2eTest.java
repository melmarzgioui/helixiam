/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 8: an unhandled server error on {@code /admin} or {@code /account} surfaces as a 500 with a correlation id
 * (and nothing internal). Before the fix {@code /error} was not permitted, so the error dispatch hit the
 * authentication entry point and every 500 came back as a 401 — which hid the realm, client and MFA failures.
 */
class ErrorSurfacingE2eTest extends AbstractE2eTest {

    @Test
    void adminServerError_isA500WithACorrelationId() {
        final E2eHttp.Response r = adminSession().get("/admin/realms/" + MASTER + "/e2e-forced-error");
        assertThat(r.status()).as(r.toString()).isEqualTo(500);
        final String id = r.json().path("correlationId").asText();
        assertThat(id).isNotBlank();
        assertThat(r.body()).doesNotContain("secret-detail-must-not-leak").doesNotContain("IllegalStateException")
                .doesNotContain("at io.helixiam");
    }

    @Test
    void accountServerError_isA500() {
        final E2eSeed.SeededUser user = seed().user(MASTER, E2eSeed.unique("err"), "Err0r-Surface-Passw0rd!");
        final E2eAdminSession session = E2eAdminSession.login(newBrowser(), MASTER, user.username(), "Err0r-Surface-Passw0rd!");
        final E2eHttp.Response r = session.get("/realms/" + MASTER + "/account/e2e-forced-error");
        assertThat(r.status()).as(r.toString()).isEqualTo(500);
        assertThat(r.json().path("correlationId").asText()).isNotBlank();
    }

    @Test
    void anonymousAdminCall_isStillA401_andAMissingRouteA404ForAnAdmin() {
        assertThat(newBrowser().get("/admin/realms/" + MASTER + "/e2e-forced-error", "Accept", "application/json").status())
                .isEqualTo(401);
        assertThat(adminSession().get("/admin/realms/" + MASTER + "/no-such-thing").status()).isEqualTo(404);
    }
}
