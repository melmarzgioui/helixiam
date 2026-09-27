/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Open issue A2: {@code prompt=login} used to loop forever. {@code PromptAndMaxAgeAuthorizeFilter} cleared the
 * session for EVERY {@code /oauth2/authorize} carrying {@code prompt=login} — including the saved request the
 * login success handler resumes right after the user signed in — so the user was sent back to {@code /login}
 * endlessly. Now the login is shown exactly once per request and the flow completes to the callback.
 */
class PromptLoginE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Prompt-Login-Passw0rd!";

    private String realm;
    private E2eSeed.SeededClient client;
    private E2eSeed.SeededUser user;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("prompt");
        seed().realm(realm);
        client = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        user = seed().user(realm, E2eSeed.unique("pat"), PASSWORD);
    }

    @Test
    void promptLogin_withoutSession_showsTheLoginOnce_andReturnsACode() {
        final OidcFlow oidc = oidc(realm);

        final OidcFlow.AuthorizationResult result = oidc.authorize("web", client.redirectUri(), user.username(),
                PASSWORD, "openid profile", null, Map.of("prompt", "login"));

        assertThat(result.code()).isNotBlank();
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", client.secret(), client.redirectUri(),
                result.code(), result.pkce().verifier());
        assertThat(oidc.verify(tokens.idToken()).getSubject()).isEqualTo(user.userId());
    }

    @Test
    void promptLogin_withAnSsoSession_forcesOneReLogin_thenReturnsACode() {
        final E2eHttp browser = newBrowser();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        oidc.authorize("web", client.redirectUri(), user.username(), PASSWORD, "openid profile");

        // Signed in: a plain authorize is silent SSO, but prompt=login must show the login page first …
        final E2eHttp.Response start = browser.followRedirectsUntil(browser.get(authorizeUrl(Map.of("prompt", "login"))),
                r -> r.locationStartsWith(client.redirectUri()));
        assertThat(start.locationStartsWith(client.redirectUri()))
                .as("prompt=login must not be answered from the SSO session: %s", start).isFalse();
        assertThat(start.status()).isEqualTo(200);
        assertThat(start.uri().getPath()).isEqualTo("/realms/" + realm + "/login");

        // … exactly once: after that sign-in the saved request resumes to the callback.
        final Map<String, String> form = new LinkedHashMap<>(E2eHttp.hiddenInputs(
                E2eHttp.form(start.body(), "name=\"password\"").orElseThrow()));
        form.put("username", user.username());
        form.put("password", PASSWORD);
        final E2eHttp.Response end = browser.followRedirectsUntil(
                browser.postForm(E2eHttp.formAction(start.body(), "name=\"password\"").orElseThrow(), form),
                r -> r.locationStartsWith(client.redirectUri()));
        assertThat(end.locationStartsWith(client.redirectUri()))
                .as("expected the callback after one re-login, got %s%n%s", end, browser.trail(12)).isTrue();
        assertThat(OidcFlow.query(end.location())).containsKey("code").containsEntry("state", "st-1");

        // A later plain authorize is silent SSO again (the prompt was consumed, not stuck on the session).
        final E2eHttp.Response silent = browser.followRedirectsUntil(browser.get(authorizeUrl(Map.of())),
                r -> r.locationStartsWith(client.redirectUri()));
        assertThat(silent.locationStartsWith(client.redirectUri())).as(silent.toString()).isTrue();

        // And a new prompt=login again asks for the password.
        final E2eHttp.Response again = browser.followRedirectsUntil(browser.get(authorizeUrl(Map.of("prompt", "login"))),
                r -> r.locationStartsWith(client.redirectUri()));
        assertThat(again.status()).as(again.toString()).isEqualTo(200);
        assertThat(again.uri().getPath()).isEqualTo("/realms/" + realm + "/login");
    }

    private String authorizeUrl(final Map<String, String> extra) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final StringBuilder url = new StringBuilder("/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web")
                .append("&redirect_uri=").append(java.net.URLEncoder.encode(client.redirectUri(), java.nio.charset.StandardCharsets.UTF_8))
                .append("&scope=openid%20profile&state=st-1&nonce=n-1")
                .append("&code_challenge=").append(pkce.challenge()).append("&code_challenge_method=S256");
        extra.forEach((k, v) -> url.append('&').append(k).append('=').append(v));
        return url.toString();
    }
}
