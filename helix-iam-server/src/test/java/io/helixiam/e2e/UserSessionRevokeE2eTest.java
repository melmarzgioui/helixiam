/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Open issue E7: {@code DELETE /admin/realms/{r}/users/{userId}/sessions} ends every session of a user in one call —
 * each SSO session (with OIDC back-channel logout, realm-signed and {@code sid}-based, to every client of it), every
 * remaining OAuth2 authorization (so every refresh token) and the browser sessions — and leaves other users alone.
 */
class UserSessionRevokeE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Revoke-All-Passw0rd!";

    private String realm;
    private String webBackchannel;
    private String portalBackchannel;
    private E2eSeed.SeededClient web;
    private E2eSeed.SeededClient portal;
    private E2eSeed.SeededUser bea;
    private E2eSeed.SeededUser other;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("revokeall");
        seed().realm(realm);
        webBackchannel = "https://app.monthfold.test/" + realm + "/auth/backchannel-logout";
        portalBackchannel = "https://portal.monthfold.test/" + realm + "/auth/backchannel-logout";
        web = seed().backchannelClient(realm, "web", List.of("openid", "profile", "email"), webBackchannel);
        portal = seed().backchannelClient(realm, "portal", List.of("openid", "profile"), portalBackchannel);
        bea = seed().user(realm, E2eSeed.unique("bea"), PASSWORD);
        other = seed().user(realm, E2eSeed.unique("otto"), PASSWORD);
    }

    private String sessionsPath(final String userId) {
        return "/admin/realms/" + realm + "/users/" + userId + "/sessions";
    }

    @Test
    void revokesEverySessionOfTheUser_withBackchannelLogoutToEveryClient_andOnlyThatUser() {
        // Browser A: web and portal in one SSO session. Browser B: web in a second SSO session.
        final E2eHttp browserA = newBrowser();
        final OidcFlow a = new OidcFlow(browserA, realm);
        final OidcFlow.Tokens aWeb = a.authorizationCode("web", web.secret(), web.redirectUri(), bea.username(),
                PASSWORD, "openid profile email");
        final OidcFlow.Tokens aPortal = a.authorizationCode("portal", portal.secret(), portal.redirectUri(),
                bea.username(), PASSWORD, "openid profile");
        final E2eHttp browserB = newBrowser();
        final OidcFlow b = new OidcFlow(browserB, realm);
        final OidcFlow.Tokens bWeb = b.authorizationCode("web", web.secret(), web.redirectUri(), bea.username(),
                PASSWORD, "openid profile email");
        final String sidA = BackchannelLogoutE2eTest.sid(a, aWeb.idToken());
        final String sidB = BackchannelLogoutE2eTest.sid(b, bWeb.idToken());
        assertThat(sidA).isNotEqualTo(sidB);

        // Another user of the same realm and client.
        final E2eHttp browserO = newBrowser();
        final OidcFlow o = new OidcFlow(browserO, realm);
        final OidcFlow.Tokens oWeb = o.authorizationCode("web", web.secret(), web.redirectUri(), other.username(),
                PASSWORD, "openid profile email");

        final E2eHttp.Response revoke = adminSession(realm).delete(sessionsPath(bea.userId()));
        assertThat(revoke.status()).as(revoke.toString()).isEqualTo(200);
        final JsonNode result = revoke.json();
        assertThat(result.path("ssoSessions").asInt()).isEqualTo(2);
        assertThat(result.path("authorizations").asInt()).as("web, portal (A) and web (B)").isEqualTo(3);

        // Back-channel logout: web gets one token per session (sidA, sidB), portal one for session A.
        final List<String> webTokens = CapturingBackchannelPoster.tokensFor(webBackchannel);
        assertThat(webTokens).hasSize(2);
        assertThat(webTokens.stream().map(t -> BackchannelLogoutE2eTest.assertValidLogoutToken(a, t, "web",
                        OidcFlow.claims(t).get("sid").toString()))
                .map(c -> {
                    assertThat(c.getSubject()).isEqualTo(bea.userId());
                    return c.getClaim("sid").toString();
                }).toList()).containsExactlyInAnyOrder(sidA, sidB);
        assertThat(CapturingBackchannelPoster.tokensFor(portalBackchannel)).hasSize(1);
        BackchannelLogoutE2eTest.assertValidLogoutToken(a, CapturingBackchannelPoster.tokensFor(portalBackchannel).get(0),
                "portal", sidA);

        // Every refresh token of the user is dead; the other user's still works.
        assertRefreshRejected(a, "web", web.secret(), aWeb.refreshToken());
        assertRefreshRejected(a, "portal", portal.secret(), aPortal.refreshToken());
        assertRefreshRejected(b, "web", web.secret(), bWeb.refreshToken());
        assertThat(o.refresh("web", web.secret(), oWeb.refreshToken()).accessToken()).isNotBlank();

        // Both browsers are signed out: silent SSO asks for a login again.
        assertThat(silentSso(browserA)).as("browser A").contains("error=login_required");
        assertThat(silentSso(browserB)).as("browser B").contains("error=login_required");
        assertThat(silentSso(browserO)).as("the other user's browser is still signed in").contains("code=");

        // A second call finds nothing left.
        final JsonNode again = adminSession(realm).delete(sessionsPath(bea.userId())).json();
        assertThat(again.path("ssoSessions").asInt()).isZero();
        assertThat(again.path("authorizations").asInt()).isZero();
    }

    @Test
    void anUnknownUser_orAUserOfAnotherRealm_isA404() {
        assertThat(adminSession(realm).delete(sessionsPath("no-such-user")).status()).isEqualTo(404);

        final String otherRealm = E2eSeed.unique("revokeother");
        seed().realm(otherRealm);
        final E2eSeed.SeededUser stranger = seed().user(otherRealm, E2eSeed.unique("tina"), PASSWORD);
        final E2eSeed.SeededClient app = seed().confidentialClient(otherRealm, E2eSeed.unique("app"), List.of("openid"));
        final OidcFlow.Tokens t = oidc(otherRealm).authorizationCode(app.clientId(), app.secret(), app.redirectUri(),
                stranger.username(), PASSWORD, "openid");

        final E2eHttp.Response cross = adminSession(realm).delete(sessionsPath(stranger.userId()));
        assertThat(cross.status()).as("another realm's user via this realm's path").isEqualTo(404);
        assertThat(oidc(otherRealm).refresh(app.clientId(), app.secret(), t.refreshToken()).accessToken())
                .as("the other realm's session is untouched").isNotBlank();
    }

    /** {@code prompt=none} authorize for web in this browser; returns the redirect's query. */
    private String silentSso(final E2eHttp browser) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String url = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + enc(web.redirectUri()) + "&scope=openid&state=s1&prompt=none"
                + "&code_challenge=" + enc(pkce.challenge()) + "&code_challenge_method=S256";
        final E2eHttp.Response r = browser.followRedirectsUntil(browser.get(url),
                hit -> hit.locationStartsWith(web.redirectUri()));
        assertThat(r.locationStartsWith(web.redirectUri())).as(r.toString()).isTrue();
        return r.location().getQuery();
    }

    private static void assertRefreshRejected(final OidcFlow oidc, final String clientId, final String secret,
                                              final String refreshToken) {
        final E2eHttp.Response r = oidc.tokenEndpoint(clientId, secret,
                Map.of("grant_type", "refresh_token", "refresh_token", refreshToken));
        assertThat(r.status()).as("refresh after revoke-all: %s", r).isEqualTo(400);
    }

    private static String enc(final String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
