/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Open issue A3: ID tokens carry {@code auth_time} (the moment of the last INTERACTIVE authentication, not the
 * last request) and {@code sid} (the SSO session), both kept on refresh. {@code sid} is the same for every client
 * signed in through one browser session and differs between browser sessions.
 */
class IdTokenSessionClaimsE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Id-Token-Claims-Passw0rd!";

    private String realm;
    private E2eSeed.SeededClient web;
    private E2eSeed.SeededClient portal;
    private E2eSeed.SeededUser user;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("idt");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        portal = seed().confidentialClient(realm, "portal", List.of("openid", "profile"));
        user = seed().user(realm, E2eSeed.unique("ida"), PASSWORD);
    }

    @Test
    void idToken_carriesAuthTimeAndSid_keptOnRefresh_andSharedAcrossClientsOfOneSession() throws Exception {
        final long before = Instant.now().getEpochSecond();
        final E2eHttp browser = newBrowser();
        final OidcFlow oidc = new OidcFlow(browser, realm);

        final OidcFlow.Tokens first = oidc.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile");
        final JWTClaimsSet id = oidc.verify(first.idToken());
        final Long authTime = authTime(id);
        final String sid = id.getStringClaim("sid");
        assertThat(authTime).as("auth_time in %s", id).isNotNull().isBetween(before, Instant.now().getEpochSecond());
        assertThat(sid).as("sid in %s", id).isNotBlank();

        // Refresh (later than the login): same auth_time (still the interactive login), same sid.
        Thread.sleep(1100);
        final OidcFlow.Tokens refreshed = oidc.refresh("web", web.secret(), first.refreshToken());
        assertThat(refreshed.idToken()).isNotBlank();
        final JWTClaimsSet rid = oidc.verify(refreshed.idToken());
        assertThat(authTime(rid)).isEqualTo(authTime);
        assertThat(rid.getStringClaim("sid")).isEqualTo(sid);

        // A second client in the same browser (silent SSO): same session, same sid, same auth_time.
        final OidcFlow.Tokens second = oidc.authorizationCode("portal", portal.secret(), portal.redirectUri(),
                user.username(), PASSWORD, "openid profile");
        final JWTClaimsSet pid = oidc.verify(second.idToken());
        assertThat(pid.getStringClaim("sid")).isEqualTo(sid);
        assertThat(authTime(pid)).as("SSO is not a new authentication").isEqualTo(authTime);

        // Another browser = another SSO session.
        final OidcFlow.Tokens other = oidc(realm).authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile");
        assertThat(oidc.verify(other.idToken()).getStringClaim("sid")).isNotBlank().isNotEqualTo(sid);
    }

    @Test
    void maxAge_reAuthentication_isVisibleInAuthTime() throws Exception {
        final E2eHttp browser = newBrowser();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        final OidcFlow.Tokens first = oidc.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile");
        final Long firstAuthTime = authTime(oidc.verify(first.idToken()));
        Thread.sleep(2100);

        // max_age=1 is exceeded: the user signs in again, and auth_time moves to that login.
        final OidcFlow.AuthorizationResult again = oidc.authorize("web", web.redirectUri(), user.username(), PASSWORD,
                "openid profile", null, Map.of("max_age", "1"));
        final OidcFlow.Tokens second = oidc.exchangeCode("web", web.secret(), web.redirectUri(), again.code(),
                again.pkce().verifier());
        final JWTClaimsSet id = oidc.verify(second.idToken());
        assertThat(authTime(id)).isNotNull().isGreaterThan(firstAuthTime);
    }

    @Test
    void promptLogin_reAuthentication_movesAuthTime_butKeepsTheSid() throws Exception {
        final E2eHttp browser = newBrowser();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        final JWTClaimsSet first = oidc.verify(oidc.authorizationCode("web", web.secret(), web.redirectUri(),
                user.username(), PASSWORD, "openid profile").idToken());
        Thread.sleep(1100);

        final OidcFlow.AuthorizationResult again = oidc.authorize("web", web.redirectUri(), user.username(), PASSWORD,
                "openid profile", null, Map.of("prompt", "login"));
        final JWTClaimsSet second = oidc.verify(oidc.exchangeCode("web", web.secret(), web.redirectUri(), again.code(),
                again.pkce().verifier()).idToken());
        assertThat(authTime(second)).isGreaterThan(authTime(first));
        assertThat(second.getStringClaim("sid")).as("same browser session").isEqualTo(first.getStringClaim("sid"));
    }

    private static Long authTime(final JWTClaimsSet claims) {
        final Object value = claims.getClaim("auth_time");
        if (value instanceof java.util.Date date) {
            return date.toInstant().getEpochSecond();
        }
        return value instanceof Number n ? n.longValue() : null;
    }
}
