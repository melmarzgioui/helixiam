/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The console's email preview shows exactly what is sent: the branded layout, a real button, escaped values. */
class EmailPreviewE2eTest extends AbstractE2eTest {

    @Test
    void htmlPreviewIsTheBrandedEmail() {
        final String realm = E2eSeed.unique("mail");
        seed().realm(realm, "Monthfold");
        final E2eAdminSession admin = adminSession(realm);
        final E2eHttp.Response r = admin.post("/admin/realms/" + realm + "/messaging/templates/preview", Map.of(
                "subject", "Sign in to {{realm}}",
                "body", "<p>Hi {{user}}</p><p><a href=\"{{link}}\" data-button>Sign in</a></p>",
                "variables", Map.of("realm", "Monthfold", "user", "<b>Ada</b>", "link", "https://idp.example/v?t=1"),
                "html", true));
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
        final String body = r.json().path("body").asText();
        assertThat(body).startsWith("<!DOCTYPE html>").contains(">Monthfold<").contains("&lt;b&gt;Ada&lt;/b&gt;")
                .contains("bgcolor=\"#").doesNotContain("data-button");

        final E2eHttp.Response plain = admin.post("/admin/realms/" + realm + "/messaging/templates/preview",
                Map.of("subject", "x", "body", "Code {{code}}", "variables", Map.of("code", "123456")));
        assertThat(plain.json().path("body").asText()).isEqualTo("Code 123456");
    }
}
