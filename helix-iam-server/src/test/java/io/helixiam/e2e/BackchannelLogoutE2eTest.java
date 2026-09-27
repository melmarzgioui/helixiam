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
 * </ul>
 *
 * Every {@code logout_token} is validated the way an RP must: signature against the realm JWKS, {@code iss},
 * {@code aud}, {@code iat}, {@code jti}, the back-channel {@code events} member, {@code sid}/{@code sub}, no
 * {@code nonce}.
 */
class BackchannelLogoutE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Backchannel-Logout-Passw0rd!";
    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

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

        // Every authorization of session A is gone (including web's older one); session B is untouched.
        assertRefreshRejected(a, "web", web.secret(), aWeb.refreshToken());
        assertRefreshRejected(a, "web", web.secret(), aWeb2.refreshToken());
        assertRefreshRejected(a, "portal", portal.secret(), aPortal.refreshToken());
        assertThat(b.refresh("web", web.secret(), bWeb.refreshToken()).accessToken()).isNotBlank();
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
