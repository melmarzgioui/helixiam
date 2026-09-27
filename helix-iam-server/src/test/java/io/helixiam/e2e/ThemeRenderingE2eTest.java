/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Structured theming, rendering half (spec §2, §4 serving, §6): the public {@code /realms/{realm}/theme.css} (headers,
 * ETag/304, organization precedence, realm scoping of {@code ?org=}), the pages that link it, the per-realm CSP, and
 * the realm's supported locales — all over real HTTP.
 */
class ThemeRenderingE2eTest extends AbstractE2eTest {

    private static final Pattern ETAG = Pattern.compile("\"[0-9a-f]{64}\"");

    private String realm;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("render");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
    }

    private String themePath() {
        return "/admin/realms/" + realm + "/theme";
    }

    private E2eHttp.Response css(final String query, final String... headers) {
        return newBrowser().get("/realms/" + realm + "/theme.css" + query, headers);
    }

    private static Map<String, Object> monthfold() {
        return Map.of(
                "colors", Map.of("primary", Map.of("light", "#1f4d47", "dark", "#7fb8ac"),
                        "surface", Map.of("light", "#f7f8f6", "dark", "#111615"),
                        "ink", Map.of("light", "#16211f", "dark", "#e8eeec")),
                "shape", Map.of("radius", 6),
                "assets", Map.of("logoUrl", "https://cdn.monthfold.example/logo.svg",
                        "faviconUrl", "https://cdn.monthfold.example/favicon.png"),
                "layout", Map.of("layout", "split", "showLanguageSwitcher", false, "supportedLocales", List.of("en")),
                "texts", Map.of("brandHeadline", "Monthly reports your clients will actually read.",
                        "brandSubhead", "Bookkeeping for small firms.", "brandByline", "", "brandBadges", List.of(),
                        "welcomeText", "Welcome back.", "footerText", "© Monthfold BV"),
                "links", Map.of("privacyUrl", "https://monthfold.example/privacy",
                        "termsUrl", "https://monthfold.example/terms"));
    }

    @Test
    void themeCss_isPublicCacheableAndStronglyVersioned_with304() {
        final E2eHttp.Response first = css("");
        assertThat(first.status()).as(first.toString()).isEqualTo(200);
        assertThat(first.header("Content-Type").orElseThrow().replace(" ", "")).isEqualToIgnoringCase("text/css;charset=utf-8");
        assertThat(first.header("Cache-Control").orElseThrow()).isEqualTo("public, max-age=300");
        assertThat(first.header("X-Content-Type-Options").orElseThrow()).isEqualTo("nosniff");
        assertThat(first.header("Set-Cookie")).as("cacheable by shared caches: no cookie").isEmpty();
        final String etag = first.header("ETag").orElseThrow();
        assertThat(etag).matches(ETAG);
        assertThat(first.body()).contains(":root {", "--hx-primary: #2f6b52;", "@media (prefers-color-scheme: dark)")
                .doesNotContain("<");

        final E2eHttp.Response notModified = css("", "If-None-Match", etag);
        assertThat(notModified.status()).isEqualTo(304);
        assertThat(notModified.body()).isEmpty();
        assertThat(notModified.header("ETag").orElseThrow()).isEqualTo(etag);

        final E2eHttp.BytesResponse head = newBrowser().head("/realms/" + realm + "/theme.css");
        assertThat(head.status()).isEqualTo(200);
        assertThat(head.header("ETag").orElseThrow()).isEqualTo(etag);

        // A theme change changes the stylesheet, its ETag, and the ?v= the pages link.
        assertThat(admin.put(themePath(), monthfold()).status()).isEqualTo(200);
        final E2eHttp.Response changed = css("", "If-None-Match", etag);
        assertThat(changed.status()).isEqualTo(200);
        final String newEtag = changed.header("ETag").orElseThrow();
        assertThat(newEtag).matches(ETAG).isNotEqualTo(etag);
        assertThat(changed.body()).contains("--hx-primary: #1f4d47;", "--hx-radius: 6px;");
        final String login = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html").body();
        assertThat(login).contains("href=\"/realms/" + realm + "/theme.css?v=" + newEtag.substring(1, 17) + "\"");

        assertThat(newBrowser().get("/realms/no-such-realm-x/theme.css").status()).isEqualTo(404);
    }

    @Test
    void theOrganizationThemeOverridesPerField_onlyWithTheOrganization_andOnlyForAnOrganizationOfTheRealm() {
        assertThat(admin.put(themePath(), monthfold()).status()).isEqualTo(200);
        final String orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", E2eSeed.unique("hp")))
                .json().path("orgId").asText();
        final E2eHttp.Response orgTheme = admin.put("/admin/realms/" + realm + "/organizations/" + orgId + "/theme",
                Map.of("colors", Map.of("primary", Map.of("light", "#6d28d9")),
                        "assets", Map.of("logoUrl", "https://cdn.harborpine.example/logo.svg")));
        assertThat(orgTheme.status()).as(orgTheme.toString()).isEqualTo(200);

        final String realmCss = css("").body();
        final String orgCss = css("?org=" + orgId).body();
        assertThat(realmCss).contains("--hx-primary: #1f4d47;").doesNotContain("#6d28d9");
        assertThat(orgCss).as("organization primary").contains("--hx-primary: #6d28d9;")
                .as("realm surface, not set by the organization").contains("--hx-surface: #f7f8f6;")
                .as("realm radius").contains("--hx-radius: 6px;");

        // Another realm's organization (and an unknown id) gets the realm theme, never an error.
        final String other = E2eSeed.unique("other");
        seed().realm(other);
        final String foreignOrg = adminSession(other).post("/admin/realms/" + other + "/organizations",
                Map.of("name", E2eSeed.unique("foreign"))).json().path("orgId").asText();
        final E2eHttp.Response foreign = css("?org=" + foreignOrg);
        assertThat(foreign.status()).isEqualTo(200);
        assertThat(foreign.body()).isEqualTo(realmCss);
        assertThat(css("?org=nope").body()).isEqualTo(realmCss);
        // ...and a realm's own organization id used on another realm's path is not honoured either.
        assertThat(newBrowser().get("/realms/" + other + "/theme.css?org=" + orgId).body()).doesNotContain("#6d28d9");

        // Pages: no organization in context → the realm's link and logo; the organization's only with its hint.
        final String plain = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html").body();
        assertThat(plain).doesNotContain("org=" + orgId).doesNotContain("cdn.harborpine.example")
                .contains("https://cdn.monthfold.example/logo.svg");
    }

    @Test
    void aFullyThemedRealm_showsItsBrandOnTheReachablePages_withoutHelixWording() {
        assertThat(admin.put(themePath(), monthfold()).status()).isEqualTo(200);
        final ObjectNode settings = (ObjectNode) admin.get("/admin/realms/" + realm + "/settings").json();
        settings.put("registrationEnabled", true);
        assertThat(admin.put("/admin/realms/" + realm + "/settings", settings).status()).isEqualTo(200);

        for (final String path : List.of("/login", "/register", "/reset/password")) {
            final E2eHttp.Response page = newBrowser().get("/realms/" + realm + path, "Accept", "text/html",
                    "Accept-Language", "nl");
            assertThat(page.status()).as(path).isEqualTo(200);
            assertThat(page.body()).as(path)
                    .contains("/realms/" + realm + "/theme.css?v=")
                    .contains("href=\"https://cdn.monthfold.example/favicon.png\"")
                    .contains("src=\"https://cdn.monthfold.example/logo.svg\"")
                    .contains("© Monthfold BV")
                    .contains("href=\"https://monthfold.example/privacy\"")
                    .doesNotContain("HelixIAM").doesNotContain("Helix<b>IAM").doesNotContain("helixiam.com")
                    .doesNotContainIgnoringCase("<style").doesNotContain(" style=");
            assertThat(page.body()).as(path + ": English only, whatever the browser asks").doesNotContain("lang=\"nl\"");
        }
        final String login = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html",
                "Accept-Language", "nl").body();
        assertThat(login).contains("Monthly reports your clients will actually read.", "Welcome back.", ">Sign in<")
                .doesNotContain("Inloggen").doesNotContain("brand-badges").doesNotContain("kd-spark");
    }

    @Test
    void theCsp_hasNoUnsafeInlineStyles_andAllowsOnlyTheRealmsImageOrigins() {
        final String before = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html")
                .header("Content-Security-Policy").orElseThrow();
        assertThat(directive(before, "style-src")).isEqualTo("style-src 'self'");
        assertThat(directive(before, "img-src")).isEqualTo("img-src 'self' data:");
        assertThat(before).doesNotContain("unsafe-inline").doesNotContain("challenges.cloudflare.com")
                .doesNotContain("www.google.com").contains("script-src 'self';").contains("form-action 'self'");

        assertThat(admin.put(themePath(), monthfold()).status()).isEqualTo(200);
        final String after = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html")
                .header("Content-Security-Policy").orElseThrow();
        assertThat(directive(after, "img-src")).isEqualTo("img-src 'self' data: https://cdn.monthfold.example");
        assertThat(after).doesNotContain(" https:;").doesNotContain("unsafe-inline");

        // Per realm: another realm does not inherit this realm's origins.
        final String other = E2eSeed.unique("plain");
        seed().realm(other);
        assertThat(directive(newBrowser().get("/realms/" + other + "/login", "Accept", "text/html")
                .header("Content-Security-Policy").orElseThrow(), "img-src")).isEqualTo("img-src 'self' data:");

        // CAPTCHA provider hosts appear only when the realm enables CAPTCHA. A fresh realm, configured before any of
        // its pages is served (realm settings are cached for 30 s on the page side).
        final String captchaRealm = E2eSeed.unique("captcha");
        seed().realm(captchaRealm);
        final E2eAdminSession master = adminSession();
        final ObjectNode settings = (ObjectNode) master.get("/admin/realms/" + captchaRealm + "/settings").json();
        settings.put("captchaProvider", "turnstile");
        settings.put("captchaSiteKey", "1x00000000000000000000AA");
        settings.put("captchaSecretKey", "1x0000000000000000000000000000000AA");
        final E2eHttp.Response saved = master.put("/admin/realms/" + captchaRealm + "/settings", settings);
        assertThat(saved.status()).as(saved.toString()).isEqualTo(200);
        final E2eHttp.Response captcha = newBrowser().get("/realms/" + captchaRealm + "/login", "Accept", "text/html");
        final String withCaptcha = captcha.header("Content-Security-Policy").orElseThrow();
        assertThat(directive(withCaptcha, "script-src")).isEqualTo("script-src 'self' https://challenges.cloudflare.com");
        assertThat(directive(withCaptcha, "frame-src")).isEqualTo("frame-src https://challenges.cloudflare.com");
        assertThat(captcha.body()).contains("cf-turnstile");

        // theme.css itself and the admin API are not pages; the asset endpoint keeps its own policy.
        assertThat(css("").header("Content-Security-Policy").orElse("")).doesNotContain("unsafe-inline");
    }

    private static String directive(final String csp, final String name) {
        for (final String d : csp.split(";")) {
            if (d.strip().startsWith(name + " ") || d.strip().equals(name)) {
                return d.strip();
            }
        }
        throw new AssertionError("No " + name + " in " + csp);
    }
}
