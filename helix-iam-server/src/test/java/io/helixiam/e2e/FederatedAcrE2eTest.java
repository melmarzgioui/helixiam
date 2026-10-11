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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 3: the brokered level of assurance reaches the ID token {@code acr}. Drives the post-broker half of
 * a federated sign-in through the test-only {@code e2e/FederatedLoginStubController} (which calls the real
 * {@link io.helixiam.authorization.federation.FederatedLoginCompleter}), the same seam
 * {@code FederatedSessionRotationBrowserE2eTest} uses for Task 2 — but over plain HTTP instead of a real
 * browser, matching {@code IdTokenSessionClaimsE2eTest} / {@code OidcFlowSmokeE2eTest}.
 */
class FederatedAcrE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Federated-Acr-Passw0rd-2026!";
    private static final String LOA = "http://eidas.europa.eu/LoA/substantial";

    private String realm;
    private E2eSeed.SeededClient web;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("acr");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
    }

    @Test
    void federatedLoginWithLoa_putsItInTheIdTokenAcr_andKeepsItOnRefresh() throws Exception {
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eHttp http = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri="
                + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge=" + pkce.challenge()
                + "&code_challenge_method=S256";

        // Anonymous authorize saves the request and lands on /login — the real FederationBrokerController
        // would redirect here too before the IdP round-trip; the stub skips straight to the post-broker half.
        final E2eHttp.Response loginPage = http.followRedirects(http.get(authorize, "Accept", "text/html"));
        assertThat(loginPage.uri().getPath()).endsWith("/login");

        final E2eHttp.Response signedIn = http.followRedirectsUntil(
                http.get("/realms/" + realm + "/broker/e2e-stub/complete?userId=" + ada.userId() + "&loa=" + encode(LOA)),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + http.trail(10)).isTrue();
        final String code = OidcFlow.query(signedIn.location()).get("code");

        final OidcFlow oidc = new OidcFlow(http, realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI, code, pkce.verifier());
        final JWTClaimsSet id = oidc.verify(tokens.idToken());
        assertThat(id.getSubject()).isEqualTo(ada.userId());
        assertThat(id.getStringClaim("acr")).as("acr in %s", id).isEqualTo(LOA);

        // Kept on refresh, same as auth_time/sid.
        final OidcFlow.Tokens refreshed = oidc.refresh("web", web.secret(), tokens.refreshToken());
        assertThat(oidc.verify(refreshed.idToken()).getStringClaim("acr")).isEqualTo(LOA);
    }

    @Test
    void federatedLoginWithoutLoa_hasNoAcrClaim() throws Exception {
        final E2eSeed.SeededUser bob = seed().user(realm, E2eSeed.unique("bob"), PASSWORD);
        final E2eHttp http = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri="
                + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge=" + pkce.challenge()
                + "&code_challenge_method=S256";
        http.followRedirects(http.get(authorize, "Accept", "text/html"));

        final E2eHttp.Response signedIn = http.followRedirectsUntil(
                http.get("/realms/" + realm + "/broker/e2e-stub/complete?userId=" + bob.userId()), // no loa param
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + http.trail(10)).isTrue();
        final String code = OidcFlow.query(signedIn.location()).get("code");

        final OidcFlow oidc = new OidcFlow(http, realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI, code, pkce.verifier());
        assertThat(oidc.verify(tokens.idToken()).getClaim("acr")).isNull();
    }

    @Test
    void passwordLogin_hasNoAcrClaim() throws Exception {
        final E2eSeed.SeededUser carol = seed().user(realm, E2eSeed.unique("carol"), PASSWORD);
        final OidcFlow oidc = oidc(realm);

        final OidcFlow.Tokens tokens = oidc.authorizationCode("web", web.secret(), web.redirectUri(),
                carol.username(), PASSWORD, "openid profile");

        assertThat(oidc.verify(tokens.idToken()).getClaim("acr")).isNull();
    }

    /**
     * [Important fix round 1] Stale acr: a password re-login in the SAME browser session, after a
     * federated login that asserted a high LoA, must NOT be bound with that old acr. Without clearing it
     * at the {@code AuthTimeStamper.stamp} choke point, {@code SsoSessionBindingAuthorizationService}
     * would copy the stale {@code HELIX_ACR} onto the new authorization.
     */
    @Test
    void passwordReLogin_afterAFederatedLoaLogin_hasNoAcr() throws Exception {
        final E2eSeed.SeededUser dana = seed().user(realm, E2eSeed.unique("dana"), PASSWORD);
        final E2eHttp http = newBrowser();
        final OidcFlow oidc = new OidcFlow(http, realm);

        // 1. Federated login asserting a high LoA.
        final OidcFlow.Pkce pkce1 = OidcFlow.Pkce.create();
        final String authorize1 = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri="
                + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st1&code_challenge=" + pkce1.challenge()
                + "&code_challenge_method=S256";
        http.followRedirects(http.get(authorize1, "Accept", "text/html"));
        final E2eHttp.Response signedIn1 = http.followRedirectsUntil(
                http.get("/realms/" + realm + "/broker/e2e-stub/complete?userId=" + dana.userId() + "&loa=" + encode(LOA)),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn1.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn1 + "\n" + http.trail(10)).isTrue();
        final String code1 = OidcFlow.query(signedIn1.location()).get("code");
        final OidcFlow.Tokens tokens1 = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI, code1, pkce1.verifier());
        assertThat(oidc.verify(tokens1.idToken()).getStringClaim("acr")).as("sanity: the first login has acr").isEqualTo(LOA);

        // 2. Re-authenticate with the password in the SAME browser (prompt=login forces a fresh interactive
        // login, mirroring max_age re-auth) — this must NOT inherit the previous login's acr.
        final OidcFlow.AuthorizationResult again = oidc.authorize("web", web.redirectUri(), dana.username(), PASSWORD,
                "openid profile", null, java.util.Map.of("prompt", "login"));
        final OidcFlow.Tokens tokens2 = oidc.exchangeCode("web", web.secret(), web.redirectUri(), again.code(),
                again.pkce().verifier());
        assertThat(oidc.verify(tokens2.idToken()).getClaim("acr")).isNull();
    }

    private static String encode(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
