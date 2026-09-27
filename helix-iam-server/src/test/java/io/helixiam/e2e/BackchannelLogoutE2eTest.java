/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OIDC Back-Channel Logout, as a relying party on another origin sees it (open issues A4, A5, A9).
 *
 * <ul>
 *   <li>A4: RP-initiated logout finds the SSO session by the {@code id_token_hint}'s {@code sid} (it used to look
 *       it up by {@code sub}, found nothing and never called any {@code backchannel_logout_uri}), and notifies
 *       every client that took part in that session — and no other session of the same user.</li>
 *   <li>A5: a session revoked by an admin (an {@code /admin/**} request, outside any realm route) is announced
 *       with tokens signed by the SESSION's realm key and carrying that realm's issuer — they used to be signed
 *       with the master realm's key, so every RP validating against its realm JWKS rejected them.</li>
 *   <li>A9: logout tokens carry a short {@code exp} and a {@code jti} unique per token, so an RP can reject a
 *       replay (see {@code docs/oidc-sessions-and-logout.md}).</li>
 * </ul>
 *
 * Every {@code logout_token} is validated the way an RP must: signature against the realm JWKS, {@code iss},
 * {@code aud}, {@code iat}, {@code jti}, the back-channel {@code events} member, {@code sid}/{@code sub}, no
 * {@code nonce}.
 */
class BackchannelLogoutE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Backchannel-Logout-Passw0rd!";
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";
    /** A9: logout tokens are short-lived (the default is 120 s). */
    private static final long MAX_LOGOUT_TOKEN_LIFETIME = 300;

    private String realm;
    private String webBackchannel;
    private String portalBackchannel;
    private E2eSeed.SeededClient web;
    private E2eSeed.SeededClient portal;
    private E2eSeed.SeededUser user;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("bcl");
        seed().realm(realm);
        webBackchannel = "https://app.monthfold.test/" + realm + "/auth/backchannel-logout";
        portalBackchannel = "https://portal.monthfold.test/" + realm + "/auth/backchannel-logout";
        web = seed().backchannelClient(realm, "web", List.of("openid", "profile", "email"), webBackchannel);
        portal = seed().backchannelClient(realm, "portal", List.of("openid", "profile"), portalBackchannel);
        user = seed().user(realm, E2eSeed.unique("bea"), PASSWORD);
    }

    @Test
    void rpInitiatedLogout_notifiesEveryClientOfThatSession_bySid_andOnlyThatSession() {
        // Browser A: web, then portal by SSO, then web again after prompt=login (a second authorization for web).
        final E2eHttp browserA = newBrowser();
        final OidcFlow a = new OidcFlow(browserA, realm);
        final OidcFlow.Tokens aWeb = a.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile email");
        final OidcFlow.Tokens aPortal = a.authorizationCode("portal", portal.secret(), portal.redirectUri(),
                user.username(), PASSWORD, "openid profile");
        final OidcFlow.AuthorizationResult reLogin = a.authorize("web", web.redirectUri(), user.username(), PASSWORD,
                "openid profile email", null, Map.of("prompt", "login"));
        final OidcFlow.Tokens aWeb2 = a.exchangeCode("web", web.secret(), web.redirectUri(), reLogin.code(),
                reLogin.pkce().verifier());
        final String sidA = sid(a, aWeb.idToken());
        assertThat(sid(a, aPortal.idToken())).isEqualTo(sidA);

        // Browser B: the same user, another SSO session.
        final OidcFlow b = oidc(realm);
        final OidcFlow.Tokens bWeb = b.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile email");
        assertThat(sid(b, bWeb.idToken())).isNotEqualTo(sidA);

        // The RP signs out of browser A's session.
        final E2eHttp.Response logout = browserA.get("/realms/" + realm + "/connect/logout?id_token_hint="
                + enc(aWeb.idToken()) + "&post_logout_redirect_uri=" + enc(E2eSeed.POST_LOGOUT_REDIRECT_URI)
                + "&state=bye");
        assertThat(logout.locationStartsWith(E2eSeed.POST_LOGOUT_REDIRECT_URI)).as(logout.toString()).isTrue();

        // Back-channel logout reached both clients of session A, once each, with a valid logout_token.
        assertThat(CapturingBackchannelPoster.tokensFor(webBackchannel)).hasSize(1);
        assertThat(CapturingBackchannelPoster.tokensFor(portalBackchannel)).hasSize(1);
        assertValidLogoutToken(a, CapturingBackchannelPoster.tokensFor(webBackchannel).get(0), "web", sidA);
        assertValidLogoutToken(a, CapturingBackchannelPoster.tokensFor(portalBackchannel).get(0), "portal", sidA);

        // Session B is untouched by A's logout.
        final OidcFlow.Tokens bRefreshed = b.refresh("web", web.secret(), bWeb.refreshToken());
        assertThat(bRefreshed.accessToken()).isNotBlank();

        // A9: every logout_token has its own jti (RPs reject a repeated one), also across logouts.
        final E2eHttp.Response revokeB = adminSession().delete("/admin/realms/" + realm + "/sessions/"
                + enc(sid(b, bWeb.idToken())));
        assertThat(revokeB.status()).as(revokeB.toString()).isEqualTo(204);
        final List<String> jtis = new java.util.ArrayList<>();
        for (final String t : CapturingBackchannelPoster.tokensFor(webBackchannel)) {
            jtis.add(OidcFlow.claims(t).get("jti").toString());
        }
        jtis.add(OidcFlow.claims(CapturingBackchannelPoster.tokensFor(portalBackchannel).get(0)).get("jti").toString());
        assertThat(jtis).hasSize(3).doesNotHaveDuplicates();

        // Every authorization of session A is gone (including web's older one).
        assertRefreshRejected(a, "web", web.secret(), aWeb.refreshToken());
        assertRefreshRejected(a, "web", web.secret(), aWeb2.refreshToken());
        assertRefreshRejected(a, "portal", portal.secret(), aPortal.refreshToken());
    }

    @Test
    void adminRevoke_sendsLogoutTokensSignedWithTheSessionRealmsKey_andIssuer() {
        final OidcFlow a = oidc(realm);
        final OidcFlow.Tokens aWeb = a.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile email");
        a.authorizationCode("portal", portal.secret(), portal.redirectUri(), user.username(), PASSWORD, "openid profile");
        final String sidA = sid(a, aWeb.idToken());

        // The master realm's admin revokes the session from the console (an /admin/** request: no realm route).
        final E2eHttp.Response revoke = adminSession().delete("/admin/realms/" + realm + "/sessions/" + enc(sidA));
        assertThat(revoke.status()).as(revoke.toString()).isEqualTo(204);

        // A5: the tokens verify against THIS realm's JWKS (not master's) and carry this realm's issuer.
        assertThat(CapturingBackchannelPoster.tokensFor(webBackchannel)).hasSize(1);
        assertThat(CapturingBackchannelPoster.tokensFor(portalBackchannel)).hasSize(1);
        final JWTClaimsSet webToken = assertValidLogoutToken(a,
                CapturingBackchannelPoster.tokensFor(webBackchannel).get(0), "web", sidA);
        assertValidLogoutToken(a, CapturingBackchannelPoster.tokensFor(portalBackchannel).get(0), "portal", sidA);
        assertThat(webToken.getIssuer()).isEqualTo(baseUrl() + "/realms/" + realm);
        assertThat(webToken.getSubject()).isEqualTo(user.userId());
        assertRefreshRejected(a, "web", web.secret(), aWeb.refreshToken());
    }

    @Test
    void realmAdminRevoke_isSignedWithTheRealmKeyToo() {
        final OidcFlow a = oidc(realm);
        final OidcFlow.Tokens aWeb = a.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile email");
        final String sidA = sid(a, aWeb.idToken());

        final E2eHttp.Response revoke = adminSession(realm).delete("/admin/realms/" + realm + "/sessions/" + enc(sidA));
        assertThat(revoke.status()).as(revoke.toString()).isEqualTo(204);

        assertThat(CapturingBackchannelPoster.tokensFor(webBackchannel)).hasSize(1);
        assertValidLogoutToken(a, CapturingBackchannelPoster.tokensFor(webBackchannel).get(0), "web", sidA);
    }

    @Test
    void logoutEndsOnlyThatSessionsBrowserLogin_notTheUsersOtherBrowsers() {
        final E2eHttp browserA = newBrowser();
        final OidcFlow a = new OidcFlow(browserA, realm);
        final OidcFlow.Tokens aWeb = a.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile email");
        final E2eHttp browserB = newBrowser();
        final OidcFlow b = new OidcFlow(browserB, realm);
        b.authorizationCode("web", web.secret(), web.redirectUri(), user.username(), PASSWORD, "openid profile email");
        final E2eHttp browserC = newBrowser();
        final OidcFlow c = new OidcFlow(browserC, realm);
        final OidcFlow.Tokens cWeb = c.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile email");

        // RP-initiated logout of browser A: browsers B and C stay signed in (silent SSO, no login prompt).
        final E2eHttp.Response logout = browserA.get("/realms/" + realm + "/connect/logout?id_token_hint="
                + enc(aWeb.idToken()) + "&post_logout_redirect_uri=" + enc(E2eSeed.POST_LOGOUT_REDIRECT_URI));
        assertThat(logout.locationStartsWith(E2eSeed.POST_LOGOUT_REDIRECT_URI)).as(logout.toString()).isTrue();
        assertThat(silentAuthorize(browserA).locationStartsWith(web.redirectUri())).as("A is signed out").isFalse();
        assertThat(silentAuthorize(browserB).locationStartsWith(web.redirectUri())).as("B still signed in").isTrue();
        assertThat(silentAuthorize(browserC).locationStartsWith(web.redirectUri())).as("C still signed in").isTrue();

        // An admin revoke of browser C's session signs THAT browser out (its HTTP session is ended too), not B.
        final E2eHttp.Response revoke = adminSession().delete("/admin/realms/" + realm + "/sessions/"
                + enc(sid(c, cWeb.idToken())));
        assertThat(revoke.status()).as(revoke.toString()).isEqualTo(204);
        final E2eHttp.Response cAfter = silentAuthorize(browserC);
        assertThat(cAfter.locationStartsWith(web.redirectUri())).as("C must sign in again: %s", cAfter).isFalse();
        assertThat(cAfter.uri().getPath()).isEqualTo("/realms/" + realm + "/login");
        assertThat(silentAuthorize(browserB).locationStartsWith(web.redirectUri())).as("B still signed in").isTrue();
    }

    /** A plain authorize request in {@code browser}: a redirect to the callback when its session is signed in. */
    private E2eHttp.Response silentAuthorize(final E2eHttp browser) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String url = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri="
                + enc(web.redirectUri()) + "&scope=openid&state=s&nonce=n&code_challenge=" + pkce.challenge()
                + "&code_challenge_method=S256";
        return browser.followRedirectsUntil(browser.get(url), r -> r.locationStartsWith(web.redirectUri()));
    }

    /** Validates a logout_token exactly as OIDC Back-Channel Logout 1.0 §2.6 asks an RP to. */
    static JWTClaimsSet assertValidLogoutToken(final OidcFlow oidc, final String logoutToken, final String clientId,
                                               final String sid) {
        final JWTClaimsSet claims = oidc.verify(logoutToken); // signature against the realm JWKS
        try {
            assertThat(claims.getIssuer()).isEqualTo(oidc.issuer());
            assertThat(claims.getAudience()).containsExactly(clientId);
            assertThat(claims.getIssueTime()).isNotNull();
            assertThat(claims.getJWTID()).isNotBlank();
            assertThat(claims.getJSONObjectClaim("events")).containsOnlyKeys(EVENT);
            assertThat(claims.getJSONObjectClaim("events").get(EVENT)).isInstanceOf(Map.class);
            assertThat((Map<?, ?>) claims.getJSONObjectClaim("events").get(EVENT)).isEmpty();
            assertThat(claims.getStringClaim("sid")).isEqualTo(sid);
            assertThat(claims.getClaim("nonce")).as("a logout_token must not carry a nonce").isNull();
            // A9: short-lived, so a captured token cannot be replayed for long.
            assertThat(claims.getExpirationTime()).as("exp").isNotNull().isAfter(new java.util.Date());
            final long lifetime = (claims.getExpirationTime().getTime() - claims.getIssueTime().getTime()) / 1000;
            assertThat(lifetime).as("exp - iat (seconds)").isPositive().isLessThanOrEqualTo(MAX_LOGOUT_TOKEN_LIFETIME);
        } catch (final java.text.ParseException e) {
            throw new AssertionError(e);
        }
        return claims;
    }

    static String sid(final OidcFlow oidc, final String idToken) {
        try {
            return oidc.verify(idToken).getStringClaim("sid");
        } catch (final java.text.ParseException e) {
            throw new AssertionError(e);
        }
    }

    private static void assertRefreshRejected(final OidcFlow oidc, final String clientId, final String secret,
                                              final String refreshToken) {
        final E2eHttp.Response r = oidc.tokenEndpoint(clientId, secret,
                Map.of("grant_type", "refresh_token", "refresh_token", refreshToken));
        assertThat(r.status()).as("refresh after logout: %s", r).isEqualTo(400);
    }

    private static String enc(final String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
