/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 3 UI/UX review, the messages the server decides: S7 (wrong password, password mismatch, announced errors),
 * S10 (the profile shows the signed-in user's own values), S12 (required actions in words, not codes).
 */
class ThemedPageMessagesE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Page-Messages-Passw0rd!";

    private String realm;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("pages");
        seed().realm(realm, "Monthfold");
    }

    private E2eHttp.Response failedLogin(final E2eHttp http, final String language) {
        // ?lang= stores the choice in the locale cookie, so the redirect back to the login page keeps it.
        final E2eHttp.Response page = http.get("/realms/" + realm + "/login?lang=" + language, "Accept", "text/html");
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(page.body(), "name=\"password\"").orElseThrow()));
        form.put("username", "nobody@example.com");
        form.put("password", "wrong-password");
        return http.followRedirects(http.postForm(E2eHttp.formAction(page.body(), "name=\"password\"").orElseThrow(),
                form, "Accept-Language", language));
    }

    @Test
    void aWrongPassword_saysSo_onceAndAnnounced_inEnglishAndDutch() {
        final E2eHttp.Response en = failedLogin(newBrowser(), "en");
        assertThat(en.status()).isEqualTo(200);
        assertThat(en.body()).contains("role=\"alert\"").contains("Email or password is incorrect")
                .doesNotContain("Provide your email address").doesNotContain("Provide your password");

        final E2eHttp.Response nl = failedLogin(newBrowser(), "nl");
        assertThat(nl.body()).contains("role=\"alert\"").contains("E-mailadres of wachtwoord is onjuist");
    }

    @Test
    void aPasswordMismatchOnRegistration_isExplained_andTiedToTheField() {
        final ObjectNode settings = (ObjectNode) adminSession(realm).get("/admin/realms/" + realm + "/settings").json();
        settings.put("registrationEnabled", true);
        assertThat(adminSession(realm).put("/admin/realms/" + realm + "/settings", settings).status()).isEqualTo(200);

        final E2eHttp http = newBrowser();
        final E2eHttp.Response page = http.get("/realms/" + realm + "/register", "Accept", "text/html");
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(page.body(), "name=\"repeatPassword\"").orElseThrow()));
        form.put("username", E2eSeed.unique("new") + "@example.com");
        form.put("password", "One-Passw0rd!");
        form.put("repeatPassword", "Other-Passw0rd!");
        final E2eHttp.Response result = http.postForm(
                E2eHttp.formAction(page.body(), "name=\"repeatPassword\"").orElseThrow(), form);
        assertThat(result.status()).isEqualTo(200);
        assertThat(result.body()).contains("role=\"alert\"").contains("The passwords are empty or do not match.")
                .containsPattern("id=\"repeatPassword\"[^>]*aria-invalid=\"true\"")
                .containsPattern("id=\"repeatPassword\"[^>]*aria-describedby=\"password-error\"");
    }

    @Test
    void theProfileShowsTheSignedInUsersOwnValues() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("ada"), PASSWORD,
                Map.of("given_name", "Ada", "family_name", "Lovelace", "phone_number", "+31 6 1234 5678"));
        final E2eHttp http = E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD).http();
        // B1: /me is now the account console (/account), which shows the same profile values.
        final E2eHttp.Response redirect = http.get("/realms/" + realm + "/me", "Accept", "text/html");
        assertThat(redirect.isRedirect()).as(redirect.toString()).isTrue();
        assertThat(redirect.location().getPath()).isEqualTo("/realms/" + realm + "/account");
        final E2eHttp.Response me = http.get("/realms/" + realm + "/account", "Accept", "text/html");
        assertThat(me.status()).as(me.toString()).isEqualTo(200);
        assertThat(me.body()).contains(user.username() + "@e2e.helixiam.test", "Ada", "Lovelace", "+31 6 1234 5678")
                .contains(user.username()).doesNotContain(">-<");
    }

    @Test
    void aRequiredAction_isDescribedInWords() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("grace"), PASSWORD);
        final E2eHttp.Response set = adminSession(realm).put("/admin/realms/" + realm + "/users/" + user.userId()
                + "/required-actions", Map.of("requiredActions", "VERIFY_EMAIL"));
        assertThat(set.status()).as(set.toString()).isEqualTo(204);
        final E2eHttp http = E2eAdminSession.login(newBrowser(), realm, user.username(), PASSWORD).http();
        final E2eHttp.Response page = http.get("/realms/" + realm + "/required-actions", "Accept", "text/html");
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        assertThat(page.body()).contains("Verify your email address").doesNotContain("VERIFY_EMAIL");

        final E2eHttp.Response nl = http.get("/realms/" + realm + "/required-actions", "Accept", "text/html",
                "Accept-Language", "nl");
        assertThat(nl.body()).contains("Bevestig je e-mailadres");
    }
}
