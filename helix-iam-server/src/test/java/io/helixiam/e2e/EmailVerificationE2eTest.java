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
 * C3: admin email verification. {@code emailVerified} on admin create/update; {@code POST .../send-verification-email}
 * emails a single-use link; and {@code VERIFY_EMAIL} is enforced — when the realm requires verification (or the admin
 * set the action) the user is held at sign-in until the link is opened, and no tokens are issued meanwhile.
 */
class EmailVerificationE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Verify-Passw0rd!-e2e";

    private String realm;
    private E2eAdminSession admin;
    private E2eSeed.SeededClient web;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("verify");
        seed().realm(realm, "Verify");
        admin = adminSession();
        web = seed().confidentialClient(realm, "web", List.of("openid", "email"));
    }

    @Test
    void adminCreateAndUpdate_setEmailVerified() {
        final E2eHttp.Response created = admin.post("/admin/realms/" + realm + "/users", Map.of("username",
                E2eSeed.unique("ann"), "email", E2eSeed.unique("ann") + "@example.com", "password", PASSWORD,
                "emailVerified", true));
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        assertThat(created.json().path("emailVerified").asBoolean()).isTrue();
        final String id = created.json().path("userId").asText();
        final String username = created.json().path("username").asText();
        final String email = created.json().path("email").asText();

        final E2eHttp.Response unverified = admin.put("/admin/realms/" + realm + "/users/" + id,
                Map.of("username", username, "email", email, "emailVerified", false));
        assertThat(unverified.status()).as(unverified.toString()).isEqualTo(200);
        assertThat(unverified.json().path("emailVerified").asBoolean()).isFalse();

        // Omitted: unchanged.
        final E2eHttp.Response verified = admin.put("/admin/realms/" + realm + "/users/" + id,
                Map.of("username", username, "email", email, "emailVerified", true));
        assertThat(verified.json().path("emailVerified").asBoolean()).isTrue();
        final E2eHttp.Response omitted = admin.put("/admin/realms/" + realm + "/users/" + id,
                Map.of("username", username, "email", email));
        assertThat(omitted.json().path("emailVerified").asBoolean()).isTrue();

        // A created user without the flag is unverified.
        final E2eHttp.Response plain = admin.post("/admin/realms/" + realm + "/users", Map.of("username",
                E2eSeed.unique("bob"), "email", E2eSeed.unique("bob") + "@example.com", "password", PASSWORD));
        assertThat(plain.json().path("emailVerified").asBoolean()).isFalse();
    }

    @Test
    void sendVerificationEmail_emailsASingleUseLinkThatVerifiesTheAddress() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("cat"), PASSWORD);
        final String email = user.dto().email();
        final E2eHttp.Response sent = admin.post("/admin/realms/" + realm + "/users/" + user.userId()
                + "/send-verification-email", Map.of());
        assertThat(sent.status()).as(sent.toString()).isEqualTo(204);

        final List<String> links = CapturingEmailVerificationSender.linksFor(email);
        assertThat(links).hasSize(1);
        final String link = links.get(0);
        assertThat(link).startsWith(baseUrl() + "/realms/" + realm + "/verify-email?token=");
        final String token = link.substring(link.indexOf("token=") + 6);
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM email_verification_token WHERE token_hash = ?",
                Integer.class, token)).as("stored hashed").isZero();

        // GET only shows a confirmation (prefetching mail scanners cannot use it up); POST verifies once.
        final E2eHttp http = newBrowser();
        final E2eHttp.Response confirm = http.get(link, "Accept", "text/html");
        assertThat(confirm.status()).isEqualTo(200);
        assertThat(userJson(user.userId()).path("emailVerified").asBoolean()).isFalse();
        final E2eHttp.Response done = submitForm(http, confirm, "name=\"token\"");
        assertThat(done.status()).as(done.toString()).isEqualTo(200);
        assertThat(userJson(user.userId()).path("emailVerified").asBoolean()).isTrue();

        final E2eHttp other = newBrowser();
        assertThat(submitForm(other, other.get(link, "Accept", "text/html"), "name=\"token\"").status()).isEqualTo(400);

        // Already verified → 409; unknown or another realm's user → 404.
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/send-verification-email",
                Map.of()).status()).isEqualTo(409);
        final String otherRealm = E2eSeed.unique("verify");
        seed().realm(otherRealm);
        final E2eSeed.SeededUser stranger = seed().user(otherRealm, E2eSeed.unique("dan"), PASSWORD);
        assertThat(admin.post("/admin/realms/" + realm + "/users/" + stranger.userId() + "/send-verification-email",
                Map.of()).status()).isEqualTo(404);
        assertThat(CapturingEmailVerificationSender.linksFor(stranger.dto().email())).isEmpty();
    }

    @Test
    void aLinkForAnOldAddress_doesNotVerifyTheNewOne() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("eve"), PASSWORD);
        admin.post("/admin/realms/" + realm + "/users/" + user.userId() + "/send-verification-email", Map.of());
        final String link = CapturingEmailVerificationSender.linksFor(user.dto().email()).get(0);
        admin.put("/admin/realms/" + realm + "/users/" + user.userId(), Map.of("username", user.username(),
                "email", E2eSeed.unique("new") + "@example.com"));
        final E2eHttp http = newBrowser();
        assertThat(submitForm(http, http.get(link, "Accept", "text/html"), "name=\"token\"").status()).isEqualTo(400);
        assertThat(userJson(user.userId()).path("emailVerified").asBoolean()).isFalse();
    }

    @Test
    void realmRequiringVerification_holdsTheSignInUntilTheLinkIsOpened_andIssuesNoTokensMeanwhile() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("fay"), PASSWORD);
        // Signed in before the realm required verification: holds a refresh token.
        final OidcFlow.Tokens before = oidc(realm).authorizationCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                user.username(), PASSWORD, "openid email");
        assertThat(before.refreshToken()).isNotBlank();

        final E2eHttp.Response on = admin.put("/admin/realms/" + realm + "/settings/verify-email", Map.of("enabled", true));
        assertThat(on.status()).as(on.toString()).isEqualTo(200);
        assertThat(admin.get("/admin/realms/" + realm + "/settings/verify-email").json().path("enabled").asBoolean()).isTrue();

        // No tokens for the unverified user, whatever the grant.
        final E2eHttp.Response refreshed = oidc(realm).tokenEndpoint("web", web.secret(),
                Map.of("grant_type", "refresh_token", "refresh_token", before.refreshToken()));
        assertThat(refreshed.status()).as(refreshed.toString()).isEqualTo(400);
        assertThat(refreshed.json().path("error").asText()).isEqualTo("access_denied");

        // Sign-in is held on the verification page; the link was emailed on arrival.
        final E2eHttp http = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final E2eHttp.Response held = signIn(http, user.username(), pkce);
        assertThat(held.uri().getPath()).as(held + "\n" + http.trail(8)).isEqualTo("/realms/" + realm + "/required-actions");
        assertThat(held.body()).contains(user.dto().email());
        final List<String> links = CapturingEmailVerificationSender.linksFor(user.dto().email());
        assertThat(links).hasSize(1);

        // Acknowledging is not verifying; continuing before the link was opened stays on the page.
        final E2eHttp.Response ack = http.followRedirects(http.postForm("/realms/" + realm + "/required-actions/acknowledge",
                E2eHttp.hiddenInputs(E2eHttp.form(held.body(), "data-verify=\"continue\"").orElseThrow())));
        assertThat(ack.uri().getPath()).isEqualTo("/realms/" + realm + "/required-actions");
        final E2eHttp.Response notYet = submitForm(http, held, "data-verify=\"continue\"");
        assertThat(notYet.status()).isEqualTo(200);
        assertThat(notYet.uri().getPath()).endsWith("/required-actions/verify-email/continue");

        // "Send again" works (rate limited separately).
        final E2eHttp.Response resent = submitForm(http, held, "data-verify=\"resend\"");
        assertThat(resent.status()).isEqualTo(200);
        assertThat(CapturingEmailVerificationSender.linksFor(user.dto().email())).hasSize(2);

        // Open the link (another browser, e.g. the mail app), then continue → back at the client with a code.
        final E2eHttp mail = newBrowser();
        final String link = CapturingEmailVerificationSender.linksFor(user.dto().email()).get(1);
        assertThat(submitForm(mail, mail.get(link, "Accept", "text/html"), "name=\"token\"").status()).isEqualTo(200);
        final E2eHttp.Response back = http.followRedirectsUntil(submitForm(http, held, "data-verify=\"continue\""),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(back.locationStartsWith(E2eSeed.REDIRECT_URI)).as(back + "\n" + http.trail(8)).isTrue();
        final OidcFlow oidc = oidc(realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(back.location()).get("code"), pkce.verifier());
        assertThat(OidcFlow.claims(tokens.idToken()).get("email_verified")).isEqualTo(true);
    }

    @Test
    void realmRequirement_doesNotAffectUsersWithoutAnEmail_orVerifiedUsers() {
        admin.put("/admin/realms/" + realm + "/settings/verify-email", Map.of("enabled", true));
        final E2eHttp.Response noEmail = admin.post("/admin/realms/" + realm + "/users", Map.of("username",
                E2eSeed.unique("gus"), "password", PASSWORD));
        assertThat(oidc(realm).authorizationCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                noEmail.json().path("username").asText(), PASSWORD, "openid").accessToken()).isNotBlank();

        final E2eHttp.Response verified = admin.post("/admin/realms/" + realm + "/users", Map.of("username",
                E2eSeed.unique("hal"), "email", E2eSeed.unique("hal") + "@example.com", "password", PASSWORD,
                "emailVerified", true));
        assertThat(oidc(realm).authorizationCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                verified.json().path("username").asText(), PASSWORD, "openid").accessToken()).isNotBlank();
    }

    @Test
    void anExplicitVerifyEmailAction_isEnforcedEvenWhenTheRealmDoesNotRequireIt() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("ivy"), PASSWORD);
        assertThat(admin.put("/admin/realms/" + realm + "/users/" + user.userId() + "/required-actions",
                Map.of("requiredActions", "VERIFY_EMAIL")).status()).isEqualTo(204);
        final E2eHttp http = newBrowser();
        final E2eHttp.Response held = signIn(http, user.username(), OidcFlow.Pkce.create());
        assertThat(held.uri().getPath()).isEqualTo("/realms/" + realm + "/required-actions");
        final E2eHttp.Response ack = http.followRedirects(http.postForm("/realms/" + realm + "/required-actions/acknowledge",
                E2eHttp.hiddenInputs(E2eHttp.form(held.body(), "data-verify=\"continue\"").orElseThrow())));
        assertThat(ack.uri().getPath()).isEqualTo("/realms/" + realm + "/required-actions");
        assertThat(admin.get("/admin/realms/" + realm + "/users/" + user.userId() + "/required-actions").json()
                .path("requiredActions").asText()).isEqualTo("VERIFY_EMAIL");

        // Verifying clears the action.
        final String link = CapturingEmailVerificationSender.linksFor(user.dto().email()).get(0);
        final E2eHttp mail = newBrowser();
        submitForm(mail, mail.get(link, "Accept", "text/html"), "name=\"token\"");
        assertThat(admin.get("/admin/realms/" + realm + "/users/" + user.userId() + "/required-actions").json()
                .path("requiredActions").asText()).isEmpty();
    }

    /** Starts an authorization request and signs in with the password; returns the page the sign-in landed on. */
    private E2eHttp.Response signIn(final E2eHttp http, final String username, final OidcFlow.Pkce pkce) {
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri="
                + E2eSeed.REDIRECT_URI + "&scope=openid%20email&state=st&code_challenge=" + pkce.challenge()
                + "&code_challenge_method=S256";
        final E2eHttp.Response login = http.followRedirects(http.get(authorize, "Accept", "text/html"));
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(login.body(), "name=\"password\"").orElseThrow(() -> new AssertionError("no login form: " + login))));
        form.put("username", username);
        form.put("password", PASSWORD);
        return http.followRedirectsUntil(http.postForm(E2eHttp.formAction(login.body(), "name=\"password\"").orElseThrow(), form),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
    }

    private com.fasterxml.jackson.databind.JsonNode userJson(final String userId) {
        return admin.get("/admin/realms/" + realm + "/users/" + userId).json();
    }

    private static E2eHttp.Response submitForm(final E2eHttp http, final E2eHttp.Response page, final String marker) {
        return http.postForm(E2eHttp.formAction(page.body(), marker).orElseThrow(() -> new AssertionError("no form: " + page)),
                E2eHttp.hiddenInputs(E2eHttp.form(page.body(), marker).orElseThrow()));
    }
}
