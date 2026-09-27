/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 7 (branding half; verified custom domains are deferred): an organization's display name, logo and
 * primary colour are set through the admin API (validated — no raw CSS/HTML) and rendered on the login, MFA and
 * consent pages when that organization is in context via the {@code organization} authorize hint.
 */
class OrganizationBrandingE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "0rg-Branding-Passw0rd!";
    private static final String LOGO = "https://cdn.harborpine.example/logo.svg";
    private static final String COLOR = "#1F6F5C";

    private String realm;
    private String orgName;
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("firms");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
        orgName = E2eSeed.unique("harbor-pine");
        final E2eHttp.Response org = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", orgName));
        assertThat(org.status()).as(org.toString()).isEqualTo(201);
        final String orgId = org.json().path("orgId").asText();
        final E2eHttp.Response branding = admin.put(brandingPath(orgId),
                Map.of("displayName", "Harbor & Pine Accountants", "logoUrl", LOGO, "primaryColor", COLOR));
        assertThat(branding.status()).as(branding.toString()).isEqualTo(200);
        assertThat(admin.get(brandingPath(orgId)).json().path("primaryColor").asText()).isEqualTo(COLOR);
    }

    @Test
    void invalidBrandingValues_areRefused() {
        final String orgId = admin.post("/admin/realms/" + realm + "/organizations", Map.of("name", E2eSeed.unique("o")))
                .json().path("orgId").asText();
        for (final Map<String, String> bad : List.of(
                Map.of("primaryColor", "red"),
                Map.of("primaryColor", "#12345"),
                Map.of("primaryColor", "#123456; } body { display:none"),
                Map.of("logoUrl", "javascript:alert(1)"),
                Map.of("logoUrl", "http://cdn.example/logo.png"),
                Map.of("logoUrl", "https://cdn.example/a\" onerror=\"x"),
                Map.of("displayName", "<script>alert(1)</script>"),
                Map.of("displayName", "x".repeat(101)))) {
            final E2eHttp.Response r = admin.put(brandingPath(orgId), bad);
            assertThat(r.status()).as("%s -> %s", bad, r).isEqualTo(400);
            assertThat(r.json().path("fieldErrors").fieldNames().next()).isEqualTo(bad.keySet().iterator().next());
        }
        assertThat(admin.put("/admin/realms/" + realm + "/organizations/no-such-org/branding",
                Map.of("primaryColor", COLOR)).status()).isEqualTo(404);
    }

    @Test
    void organizationHint_brandsLoginMfaAndConsent_andNoHintMeansRealmBranding() {
        adminPutMfa();
        final E2eSeed.SeededClient portal = seed().consentClient(realm, "portal", List.of("openid", "profile"));
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("client"), PASSWORD);
        final E2eHttp http = newBrowser();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=portal"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=s"
                + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
                + "&organization=" + orgName;

        final E2eHttp.Response login = http.followRedirects(http.get(authorize, "Accept", "text/html"));
        assertThat(login.uri().getPath()).endsWith("/login");
        assertBranded(login, "login");

        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(login.body(), "name=\"password\"").orElseThrow()));
        form.put("username", user.username());
        form.put("password", PASSWORD);
        final E2eHttp.Response mfa = http.followRedirects(http.postForm(
                E2eHttp.formAction(login.body(), "name=\"password\"").orElseThrow(), form));
        assertThat(mfa.uri().getPath()).endsWith("/mfa/enable");
        assertBranded(mfa, "MFA enrolment");

        final Matcher secret = Pattern.compile("<code[^>]*>\\s*([A-Z2-7]{16,})\\s*</code>").matcher(mfa.body());
        assertThat(secret.find()).isTrue();
        final Map<String, String> code = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(mfa.body(), "name=\"code\"").orElseThrow()));
        code.put("code", totp(secret.group(1)));
        final E2eHttp.Response recovery = http.postForm(E2eHttp.formAction(mfa.body(), "name=\"code\"").orElseThrow(), code);
        assertBranded(recovery, "recovery codes");

        final String next = Pattern.compile("href=\"([^\"]*oauth2/authorize[^\"]*)\"").matcher(recovery.body()).results()
                .findFirst().map(m -> m.group(1).replace("&amp;", "&")).orElseThrow();
        final E2eHttp.Response consent = http.followRedirectsUntil(http.get(next, "Accept", "text/html"),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(consent.status()).as(consent.toString()).isEqualTo(200);
        assertThat(consent.body()).contains("name=\"state\"");
        assertBranded(consent, "consent");

        // Without the hint (a new browser) the realm's own branding is used.
        final E2eHttp.Response plain = newBrowser().followRedirects(newBrowser().get(
                "/realms/" + realm + "/login", "Accept", "text/html"));
        assertThat(plain.body()).doesNotContain("Harbor &amp; Pine").doesNotContain(LOGO).doesNotContain("&amp;org=");
    }

    private void adminPutMfa() {
        assertThat(admin.put("/admin/realms/" + realm + "/settings/mfa", Map.of("requireMfa", true)).status()).isEqualTo(200);
    }

    private void assertBranded(final E2eHttp.Response page, final String what) {
        assertThat(page.body()).as(what + " shows the organization name").contains("Harbor &amp; Pine Accountants");
        assertThat(page.body()).as(what + " shows the organization logo").contains("src=\"" + LOGO + "\"");
        // Structured theming: colours live in the realm's theme.css, which the page links with ?org= while the
        // organization is in context; the stylesheet then carries the organization's primary colour.
        final Matcher link = Pattern.compile("href=\"([^\"]*/theme\\.css\\?v=[0-9a-f]+&amp;org=([^\"]+))\"").matcher(page.body());
        assertThat(link.find()).as(what + " links the organization's theme.css: " + page.body()).isTrue();
        final E2eHttp.Response css = newBrowser().get(link.group(1).replace("&amp;", "&"));
        assertThat(css.status()).isEqualTo(200);
        assertThat(css.body()).as(what + " uses the organization colour").containsIgnoringCase("--hx-primary: " + COLOR + ";");
    }

    private String brandingPath(final String orgId) {
        return "/admin/realms/" + realm + "/organizations/" + orgId + "/branding";
    }

    private static String totp(final String secret) {
        try {
            return TimeBasedOneTimePasswordUtil.generateNumberString(secret, System.currentTimeMillis(),
                    TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS, TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH);
        } catch (final java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
