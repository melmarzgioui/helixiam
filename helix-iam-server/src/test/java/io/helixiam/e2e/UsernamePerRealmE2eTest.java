/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Usernames (and email addresses) are unique per realm, not across all realms: two firms can each have a "joe".
 * A user signs in only in their own realm — never with the same password at another realm's login page.
 */
class UsernamePerRealmE2eTest extends AbstractE2eTest {

    @Test
    void theSameUsernameAndEmailInTwoRealms_areTwoIndependentAccounts() {
        final String realmA = E2eSeed.unique("firm-a");
        final String realmB = E2eSeed.unique("firm-b");
        seed().realm(realmA);
        seed().realm(realmB);
        final String joe = E2eSeed.unique("joe");
        final String email = joe + "@shared.example";

        final E2eHttp.Response a = adminSession(realmA).post("/admin/realms/" + realmA + "/users",
                Map.of("username", joe, "email", email, "password", "Joe-In-Firm-A-Passw0rd!", "enabled", true));
        assertThat(a.status()).as(a.toString()).isEqualTo(201);
        final E2eHttp.Response b = adminSession(realmB).post("/admin/realms/" + realmB + "/users",
                Map.of("username", joe, "email", email, "password", "Joe-In-Firm-B-Passw0rd!", "enabled", true));
        assertThat(b.status()).as(b.toString()).isEqualTo(201);
        assertThat(a.json().path("userId").asText()).isNotEqualTo(b.json().path("userId").asText());

        // Within one realm the username stays unique.
        assertThat(adminSession(realmA).post("/admin/realms/" + realmA + "/users",
                Map.of("username", joe, "password", "Another-Passw0rd!-123", "enabled", true)).status()).isEqualTo(409);

        final E2eSeed.SeededClient webA = seed().confidentialClient(realmA, "web", List.of("openid"));
        final E2eSeed.SeededClient webB = seed().confidentialClient(realmB, "web", List.of("openid"));
        final OidcFlow.Tokens tokensA = oidc(realmA).authorizationCode("web", webA.secret(), webA.redirectUri(), joe,
                "Joe-In-Firm-A-Passw0rd!", "openid");
        final OidcFlow.Tokens tokensB = oidc(realmB).authorizationCode("web", webB.secret(), webB.redirectUri(), email,
                "Joe-In-Firm-B-Passw0rd!", "openid");
        assertThat(oidc(realmA).verify(tokensA.accessToken()).getSubject()).isEqualTo(a.json().path("userId").asText());
        assertThat(oidc(realmB).verify(tokensB.accessToken()).getSubject()).isEqualTo(b.json().path("userId").asText());

        // Firm A's password does not work at firm B's login page.
        assertThatThrownBy(() -> oidc(realmB).authorizationCode("web", webB.secret(), webB.redirectUri(), joe,
                "Joe-In-Firm-A-Passw0rd!", "openid")).hasMessageContaining("Login rejected");
    }

    @Test
    void aUserOfOneRealm_cannotSignInAtAnotherRealm() {
        final String realmA = E2eSeed.unique("firm-a");
        final String realmB = E2eSeed.unique("firm-b");
        seed().realm(realmA);
        seed().realm(realmB);
        final E2eSeed.SeededUser solo = seed().user(realmA, E2eSeed.unique("solo"), "Solo-Only-In-A-Passw0rd!");
        final E2eSeed.SeededClient webB = seed().confidentialClient(realmB, "web", List.of("openid"));

        assertThatThrownBy(() -> oidc(realmB).authorizationCode("web", webB.secret(), webB.redirectUri(),
                solo.username(), "Solo-Only-In-A-Passw0rd!", "openid")).hasMessageContaining("Login rejected");
    }

    @Test
    void selfRegistration_belongsToTheRealmItWasDoneIn() {
        final String realmA = E2eSeed.unique("firm-a");
        final String realmB = E2eSeed.unique("firm-b");
        seed().realm(realmA);
        seed().realm(realmB);
        final E2eHttp.Response open = adminSession().put("/admin/realms/" + realmA + "/settings", Map.of(
                "displayName", "Firm A", "accessTokenTtlSeconds", 3600, "refreshTokenTtlSeconds", 86400, "enabled", true,
                "passwordMinLength", 8, "registrationEnabled", true));
        assertThat(open.status()).as(open.toString()).isEqualTo(200);
        // Realm A's email goes to the test mail sink, to read the code from the sign-up email.
        assertThat(adminSession().put("/admin/realms/" + realmA + "/messaging/providers", Map.of("channel", "EMAIL",
                "driver", "HTTP", "enabled", true, "fromAddress", "no-reply@firm-a.example",
                "config", Map.of("url", io.helixiam.e2e.browser.MailSink.get().url()))).status()).isEqualTo(200);

        final String address = E2eSeed.unique("newcomer") + "@firm-a.example";
        final E2eHttp http = newBrowser();
        final E2eHttp.Response page = http.get("/realms/" + realmA + "/register", "Accept", "text/html");
        final Map<String, String> form = new java.util.LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(page.body(), "name=\"username\"").orElseThrow(() -> new AssertionError(page.toString()))));
        form.put("username", address);
        form.put("password", "Newcomer-Passw0rd!-2026");
        form.put("repeatPassword", "Newcomer-Passw0rd!-2026");
        form.put("given_name", "Nina");   // required by the default registration claims
        form.put("family_name", "Newcomer");
        final E2eHttp.Response done = http.postForm(E2eHttp.formAction(page.body(), "name=\"username\"").orElseThrow(), form);
        assertThat(done.status()).as(done.toString()).isEqualTo(200);
        assertThat(done.body()).as("registration accepted").doesNotContain("name=\"repeatPassword\"");

        // Listed as a user of realm A (with its default role).
        String userId = null;
        for (final com.fasterxml.jackson.databind.JsonNode u : adminSession().get("/admin/realms/" + realmA + "/users").json()) {
            if (address.equals(u.path("username").asText())) {
                userId = u.path("userId").asText();
                assertThat(u.path("roles").toString()).contains("user");
            }
        }
        assertThat(userId).as("registered user listed in realm A").isNotNull();

        // The account unlocks when the email address is verified (the code from the sign-up email).
        final String link = io.helixiam.e2e.browser.MailSink.get().await(address,
                m -> m.link("/register/verify/").isPresent(), java.time.Duration.ofSeconds(10))
                .link("/register/verify/").orElseThrow();
        final String code = link.substring(link.lastIndexOf('/') + 1);
        // Only the code's SHA-256 is stored, never the code itself.
        final String stored = context.getBean(org.springframework.jdbc.core.JdbcTemplate.class).queryForObject(
                "SELECT code FROM notification_code WHERE identifier = ? AND type = 'USER_SIGNUP'", String.class, userId);
        assertThat(stored).isEqualTo(io.helixiam.notification.NotificationCodePolicy.hash(code)).isNotEqualTo(code);
        assertThat(http.get("/realms/" + realmA + "/register/verify/" + code, "Accept", "text/html").status()).isLessThan(400);

        // Signs in at A, not at B.
        final E2eSeed.SeededClient webA = seed().confidentialClient(realmA, "web", List.of("openid"));
        final E2eSeed.SeededClient webB = seed().confidentialClient(realmB, "web", List.of("openid"));
        assertThat(oidc(realmA).authorizationCode("web", webA.secret(), webA.redirectUri(), address,
                "Newcomer-Passw0rd!-2026", "openid").accessToken()).isNotBlank();
        assertThatThrownBy(() -> oidc(realmB).authorizationCode("web", webB.secret(), webB.redirectUri(), address,
                "Newcomer-Passw0rd!-2026", "openid")).hasMessageContaining("Login rejected");
    }
}
