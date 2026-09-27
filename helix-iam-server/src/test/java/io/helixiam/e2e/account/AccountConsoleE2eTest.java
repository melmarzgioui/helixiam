/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.account;

import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * B1: the account console's security properties at the HTTP level — sign-in required, CSRF on every form post, a
 * session of another realm sees nothing, the realm settings also bind the JSON account API, the step-up, and rate
 * limits. The user journeys themselves are in {@code AccountConsoleBrowserE2eTest}.
 */
class AccountConsoleE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Account-Passw0rd-2026!";

    @Test
    void theConsole_needsASignIn() {
        final String realm = E2eSeed.unique("acc");
        seed().realm(realm);
        final E2eHttp.Response r = newBrowser().get("/realms/" + realm + "/account");
        assertThat(r.isRedirect()).as(r.toString()).isTrue();
        assertThat(r.location().getPath()).isEqualTo("/realms/" + realm + "/login");
    }

    @Test
    void everyFormPost_needsTheCsrfToken() {
        final String realm = E2eSeed.unique("acc");
        seed().realm(realm);
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eHttp http = E2eAdminSession.login(newBrowser(), realm, ada.username(), PASSWORD).http();
        final String account = "/realms/" + realm + "/account";

        for (final String path : new String[] {"/password", "/reauth", "/authenticator", "/authenticator/remove",
                "/recovery-codes", "/sessions/sign-out-others", "/email", "/export", "/delete"}) {
            final E2eHttp.Response r = http.postForm(account + path, Map.of("currentPassword", PASSWORD,
                    "newPassword", "Changed-Passw0rd-2026!", "confirmPassword", "Changed-Passw0rd-2026!"));
            assertThat(r.status()).as(path + ": " + r).isEqualTo(403);
        }
        // Nothing changed: the old password still signs in.
        E2eAdminSession.login(newBrowser(), realm, ada.username(), PASSWORD);
    }

    @Test
    void aSessionOfAnotherRealm_seesNothingOfThisRealm() {
        final String home = E2eSeed.unique("home");
        final String other = E2eSeed.unique("other");
        seed().realm(home);
        seed().realm(other);
        final E2eSeed.SeededUser ada = seed().user(home, E2eSeed.unique("ada"), PASSWORD);
        final E2eHttp http = E2eAdminSession.login(newBrowser(), home, ada.username(), PASSWORD).http();

        assertThat(http.get("/realms/" + home + "/account").status()).isEqualTo(200);
        final E2eHttp.Response foreign = http.get("/realms/" + other + "/account");
        assertThat(foreign.isRedirect()).as(foreign.toString()).isTrue();
        assertThat(foreign.location().getPath()).isEqualTo("/realms/" + other + "/login");
        assertThat(http.get("/realms/" + other + "/account/password").isRedirect()).isTrue();
    }

    @Test
    void theRealmSettings_alsoBindTheJsonAccountApi() {
        final String realm = E2eSeed.unique("acc");
        seed().realm(realm);
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eAdminSession session = E2eAdminSession.login(newBrowser(), realm, ada.username(), PASSWORD);
        final String api = "/realms/" + realm + "/account";

        assertThat(session.get(api + "/gdpr/export").status()).isEqualTo(200);
        adminSession().put("/admin/realms/" + realm + "/settings/account-console",
                Map.of("allowDataExport", false, "allowAuthenticatorRemoval", false));
        assertThat(session.get(api + "/gdpr/export").status()).isEqualTo(403);
        assertThat(session.delete(api + "/credentials/totp/totp").status()).isEqualTo(403);
        assertThat(session.delete(api + "/credentials/recovery-code/recovery-codes").status()).isEqualTo(403);
    }

    @Test
    void newRecoveryCodesOverTheJsonApi_needACodeOrAFreshSignIn() {
        final String realm = E2eSeed.unique("acc");
        seed().realm(realm);
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eAdminSession session = E2eAdminSession.login(newBrowser(), realm, ada.username(), PASSWORD);
        final String regen = "/realms/" + realm + "/account/mfa/recovery-codes";
        assertThat(session.post(regen, Map.of()).status()).as("no authenticator yet").isEqualTo(409);

        AccountTestSupport.enrolTotp(context, ada.userId());
        assertThat(session.post(regen, Map.of()).status()).as("fresh sign-in").isEqualTo(200);
        session.http().get("/realms/" + realm + "/e2e/age-auth-time?seconds=600");
        final E2eHttp.Response stale = session.post(regen, Map.of());
        assertThat(stale.status()).isEqualTo(403);
        assertThat(stale.body()).contains("step_up_required");
        assertThat(session.post(regen, Map.of("code", "000000")).status()).isEqualTo(400);
        assertThat(session.post(regen, Map.of("code",
                AccountTestSupport.currentCode(context, ada.userId()))).status()).isEqualTo(200);
    }

    @Test
    void passwordAttempts_areRateLimitedPerUser() {
        final String realm = E2eSeed.unique("acc");
        seed().realm(realm);
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eHttp http = E2eAdminSession.login(newBrowser(), realm, ada.username(), PASSWORD).http();
        final String path = "/realms/" + realm + "/account/password";

        String body = "";
        for (int i = 0; i < 11; i++) {
            final String page = http.get(path).body();
            final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(page));
            form.put("currentPassword", PASSWORD);
            form.put("newPassword", "Mismatch-Passw0rd-2026!");
            form.put("confirmPassword", "Other-Passw0rd-2026!!");
            body = http.postForm(path, form).body();
        }
        assertThat(body).contains("Too many attempts");
    }
}
