/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spec §7: {@code POST /admin/realms/{realm}/theme/preview} renders the login page with a proposed theme — same
 * validation as {@code PUT}, nothing saved, no session or cache side effects, {@code manage-realm} only.
 */
class ThemePreviewE2eTest extends AbstractE2eTest {

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("preview");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
    }

    private String previewPath() {
        return "/admin/realms/" + realm + "/theme/preview";
    }

    private static Map<String, Object> proposed() {
        return Map.of(
                "colors", Map.of("primary", Map.of("light", "#1f4d47", "dark", "#7fb8ac")),
                "assets", Map.of("logoUrl", "https://cdn.monthfold.example/logo.svg"),
                "texts", Map.of("brandHeadline", "Monthly reports your clients will actually read.",
                        "footerText", "© Monthfold BV"),
                "customCss", ".helix-brand h1 { letter-spacing: -0.03em; }");
    }

    @Test
    void rendersTheLoginPageWithTheProposedTheme_withoutSavingAnything() {
        final String cssBefore = newBrowser().get("/realms/" + realm + "/theme.css").header("ETag").orElseThrow();

        final E2eHttp.Response preview = admin.post(previewPath(), proposed());

        assertThat(preview.status()).as(preview.toString()).isEqualTo(200);
        assertThat(preview.header("Content-Type").orElseThrow()).startsWith("text/html");
        assertThat(preview.header("Cache-Control").orElseThrow()).contains("no-store");
        assertThat(preview.header("Set-Cookie")).as("no session or CSRF side effects").isEmpty();
        final String html = preview.body();
        assertThat(html).contains("Monthly reports your clients will actually read.", "© Monthfold BV",
                "src=\"https://cdn.monthfold.example/logo.svg\"", "id=\"loginForm\"")
                .doesNotContain("HelixIAM").doesNotContainIgnoringCase("<style").doesNotContain(" style=");

        // The stylesheet travels in the page, under a per-response nonce that only this response's CSP allows.
        final Matcher link = Pattern.compile("<link rel=\"stylesheet\" class=\"hx-theme\" "
                + "href=\"data:text/css;base64,([A-Za-z0-9+/=]+)\" nonce=\"([A-Za-z0-9_-]{16,})\">").matcher(html);
        assertThat(link.find()).as(html).isTrue();
        final String css = new String(Base64.getDecoder().decode(link.group(1)), StandardCharsets.UTF_8);
        assertThat(css).contains("--hx-primary: #1f4d47;", "--hx-primary: #7fb8ac;", "letter-spacing: -0.03em");
        final String nonce = link.group(2);
        final String csp = preview.header("Content-Security-Policy").orElseThrow();
        assertThat(csp).contains("'nonce-" + nonce + "'").contains("img-src").contains("https://cdn.monthfold.example")
                .contains("script-src 'none'").contains("form-action 'none'").contains("frame-ancestors 'self'")
                .doesNotContain("unsafe-inline");
        assertThat(html).as("no script in the preview").doesNotContain("<script");
        assertThat(html).as("the same policy as a meta tag, for iframe srcdoc")
                .contains("<meta http-equiv=\"Content-Security-Policy\" content=\""
                        + csp.replace("; frame-ancestors 'self'", "").replace("'", "&#39;") + "\">")
                .containsPattern("<base href=\"http://localhost:\\d+/\">");
        assertThat(admin.post(previewPath(), proposed()).body()).as("a fresh nonce per response").doesNotContain(nonce);

        // Nothing stored, nothing cached: the realm's layer, its theme.css and its login page are unchanged.
        final JsonNode stored = admin.get("/admin/realms/" + realm + "/theme").json();
        assertThat(stored.has("colors")).isFalse();
        assertThat(stored.has("customCss")).isFalse();
        assertThat(newBrowser().get("/realms/" + realm + "/theme.css").header("ETag").orElseThrow()).isEqualTo(cssBefore);
        assertThat(newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html").body())
                .doesNotContain("Monthly reports").contains("Helix<b>IAM</b>");
    }

    @Test
    void theSameValidationAsPut_errorsAre400WithFieldErrors() {
        final E2eHttp.Response badColour = admin.post(previewPath(), Map.of("colors", Map.of("primary", Map.of("light", "red"))));
        assertThat(badColour.status()).isEqualTo(400);
        assertThat(badColour.json().path("fieldErrors").has("colors.primary.light")).as(badColour.toString()).isTrue();

        final E2eHttp.Response unknown = admin.post(previewPath(), Map.of("colors", Map.of("primry", Map.of("light", "#000000"))));
        assertThat(unknown.status()).isEqualTo(400);
        assertThat(unknown.json().path("fieldErrors").has("colors.primry")).isTrue();

        final E2eHttp.Response css = admin.post(previewPath(), Map.of("customCss", "</style><script>alert(1)</script>"));
        assertThat(css.status()).isEqualTo(400);
        assertThat(css.json().path("fieldErrors").has("customCss")).isTrue();

        final E2eHttp.Response contrast = admin.post(previewPath(), Map.of("colors", Map.of("ink", Map.of("light", "#eeeeee"))));
        assertThat(contrast.status()).isEqualTo(400);
        assertThat(contrast.json().path("fieldErrors").toString()).contains("contrast.inkOnSurface.light");

        final E2eHttp.Response url = admin.post(previewPath(), Map.of("assets", Map.of("logoUrl", "javascript:alert(1)")));
        assertThat(url.status()).isEqualTo(400);
    }

    @Test
    void needsManageRealm_inThePathRealm() {
        assertThat(newBrowser().sendJson("POST", previewPath(), proposed()).status()).as("anonymous").isIn(401, 403);

        final E2eAdminSession orgOnly = scopedAdmin("manage-organizations");
        assertThat(orgOnly.post(previewPath(), proposed()).status()).as("manage-organizations only").isEqualTo(403);
        assertThat(scopedAdmin("manage-realm").post(previewPath(), proposed()).status()).isEqualTo(200);

        final String other = E2eSeed.unique("other");
        seed().realm(other);
        assertThat(adminSession(other).post(previewPath(), proposed()).status()).as("another realm's admin")
                .isIn(403, 404);
        assertThat(adminSession().post("/admin/realms/no-such-realm-y/theme/preview", proposed()).status())
                .isEqualTo(404);
    }

    private E2eAdminSession scopedAdmin(final String permission) {
        final String roleName = E2eSeed.unique("preview-" + permission);
        final E2eHttp.Response role = admin.post("/admin/realms/" + realm + "/roles", Map.of("name", roleName));
        assertThat(role.status()).as(role.toString()).isEqualTo(201);
        String roleId = role.json().path("roleId").asText();
        if (roleId.isBlank()) {
            for (final JsonNode r : admin.get("/admin/realms/" + realm + "/roles").json()) {
                if (roleName.equals(r.path("name").asText())) {
                    roleId = r.path("roleId").asText();
                }
            }
        }
        assertThat(admin.put("/admin/realms/" + realm + "/admin-roles/" + roleId,
                Map.of("permissions", List.of(permission))).status()).isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("scoped"), "Sc0ped-Admin-Passw0rd!");
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/roles", Map.of("roleId", roleId))
                .status()).isEqualTo(204);
        return E2eAdminSession.login(newBrowser(), realm, user.username(), user.password());
    }
}
