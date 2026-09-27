/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 6 (magic link): passwordless sign-in by emailed link, opt-in per realm. Request -> email -> confirm ->
 * signed in and the original authorization request resumes; the link works once, is stored hashed, expires after
 * 15 minutes (unit-tested), and requests are rate limited per email and per IP. Unknown addresses get the same
 * answer as known ones.
 */
class MagicLinkE2eTest extends AbstractE2eTest {

    private String realm;
    private E2eAdminSession admin;
    private E2eSeed.SeededClient web;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("magic");
        seed().realm(realm, "Monthfold");
        admin = adminSession(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
    }

    @Test
    void disabledByDefault() {
        assertThat(newBrowser().get("/realms/" + realm + "/login/magic", "Accept", "text/html").status()).isEqualTo(404);
        assertThat(newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html").body())
                .doesNotContain("/login/magic");
    }

    @Test
    void requestLinkConfirmSignedIn_linkWorksOnce_storedHashed_unknownAddressLooksTheSame() {
        enable();
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("joe"), "Unused-Passw0rd!-" + realm);
        final String email = user.dto().email();
        final E2eHttp http = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri="
                + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge=" + pkce.challenge()
                + "&code_challenge_method=S256";

        final E2eHttp.Response login = http.followRedirects(http.get(authorize, "Accept", "text/html"));
        assertThat(login.body()).contains("/realms/" + realm + "/login/magic");
        final E2eHttp.Response requestPage = http.get("/realms/" + realm + "/login/magic", "Accept", "text/html");
        assertThat(requestPage.status()).isEqualTo(200);

        final E2eHttp.Response sent = submit(http, requestPage, "email", email);
        assertThat(sent.status()).isEqualTo(200);
        final E2eHttp.Response unknown = submit(http, http.get("/realms/" + realm + "/login/magic", "Accept", "text/html"),
                "email", "nobody-" + realm + "@example.com");
        assertThat(unknown.status()).isEqualTo(200);
        assertThat(visibleText(unknown.body())).isEqualTo(visibleText(sent.body()));
        assertThat(CapturingMagicLinkSender.linksFor("nobody-" + realm + "@example.com")).isEmpty();

        final List<String> links = CapturingMagicLinkSender.linksFor(email);
        assertThat(links).hasSize(1);
        final String link = links.get(0);
        assertThat(link).startsWith(baseUrl() + "/realms/" + realm + "/login/magic/verify?token=");
        final String token = link.substring(link.indexOf("token=") + 6);

        // Stored hashed: the raw token is nowhere in the table.
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM magic_link_token WHERE token_hash = ?", Integer.class, token)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM magic_link_token WHERE realm_id = ?", Integer.class, realm)).isEqualTo(1);

        // GET only shows a confirmation (mail scanners that prefetch links cannot use it up).
        final E2eHttp.Response confirm = http.get(link, "Accept", "text/html");
        assertThat(confirm.status()).isEqualTo(200);
        assertThat(http.get(link, "Accept", "text/html").status()).isEqualTo(200);

        final E2eHttp.Response signedIn = http.followRedirectsUntil(submitForm(http, confirm, "name=\"token\""),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + http.trail(8)).isTrue();
        final String code = OidcFlow.query(signedIn.location()).get("code");
        final OidcFlow oidc = oidc(realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI, code, pkce.verifier());
        assertThat(oidc.verify(tokens.accessToken()).getSubject()).isEqualTo(user.userId());

        // Single use.
        final E2eHttp other = newBrowser();
        final E2eHttp.Response again = submitForm(other, other.get(link, "Accept", "text/html"), "name=\"token\"");
        assertThat(again.status()).isEqualTo(400);
        assertThat(other.followRedirects(other.get(authorize, "Accept", "text/html")).uri().getPath()).endsWith("/login");
    }

    @Test
    void requestsAreRateLimitedPerEmail() {
        enable();
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("maya"), "Unused-Passw0rd!-" + realm);
        final E2eHttp http = newBrowser();
        for (int i = 0; i < 8; i++) {
            assertThat(submit(http, http.get("/realms/" + realm + "/login/magic", "Accept", "text/html"), "email",
                    user.dto().email()).status()).isEqualTo(200);
        }
        assertThat(CapturingMagicLinkSender.linksFor(user.dto().email())).hasSize(5);
    }

    @Test
    void inARealmThatRequiresMfa_theLinkIsOnlyTheFirstFactor() {
        enable();
        assertThat(admin.put("/admin/realms/" + realm + "/settings/mfa", Map.of("requireMfa", true)).status()).isEqualTo(200);
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("owner"), "Unused-Passw0rd!-" + realm);
        final E2eHttp http = newBrowser();
        submit(http, http.get("/realms/" + realm + "/login/magic", "Accept", "text/html"), "email", user.dto().email());
        final String link = CapturingMagicLinkSender.linksFor(user.dto().email()).get(0);
        final E2eHttp.Response after = http.followRedirects(submitForm(http, http.get(link, "Accept", "text/html"), "name=\"token\""));
        assertThat(after.uri().getPath()).isEqualTo("/realms/" + realm + "/mfa/enable");
        assertThat(http.get("/realms/" + realm + "/account/profile", "Accept", "application/json").status())
                .as("no account access before the second factor").isIn(401, 403);
    }

    private void enable() {
        final E2eHttp.Response r = admin.put("/admin/realms/" + realm + "/settings/magic-link", Map.of("enabled", true));
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
    }

    private static E2eHttp.Response submit(final E2eHttp http, final E2eHttp.Response page, final String field, final String value) {
        final Map<String, String> fields = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(page.body(), "name=\"" + field + "\"").orElseThrow(() -> new AssertionError("no form: " + page))));
        fields.put(field, value);
        return http.postForm(E2eHttp.formAction(page.body(), "name=\"" + field + "\"").orElseThrow(), fields);
    }

    private static E2eHttp.Response submitForm(final E2eHttp http, final E2eHttp.Response page, final String marker) {
        return http.postForm(E2eHttp.formAction(page.body(), marker).orElseThrow(() -> new AssertionError("no form: " + page)),
                E2eHttp.hiddenInputs(E2eHttp.form(page.body(), marker).orElseThrow()));
    }

    /** Page text without markup and the per-request CSRF value, to compare two responses. */
    private static String visibleText(final String html) {
        return html.replaceAll("(?s)<[^>]*>", " ").replaceAll("\\s+", " ").trim();
    }
}
