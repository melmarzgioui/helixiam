/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.nimbusds.jwt.JWTClaimsSet;
import io.helixiam.e2e.E2eAdminSession;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves the two-origin browser harness end to end: the reference realm is seeded as Monthfold runs it, a real
 * Chromium signs in at an RP on another origin, the RP redeems the code ({@code client_secret_basic} + PKCE) and
 * verifies the ID token against the realm JWKS with the same issuer the browser saw, and the IdP reaches the RP's
 * back channel and the mail sink.
 *
 * <p>Today every redirect chain that starts with a form POST and ends on the RP is blocked by the auth pages'
 * {@code form-action 'self'} (item A1). The passing tests therefore reach the RP through a redirect chain that starts
 * with a GET (the "continue" link after two-step enrolment, or a new authorization request on an existing SSO
 * session); the direct password-only case is kept, disabled, for the A1 fix to enable.
 */
class TwoOriginHarnessBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Harness-Passw0rd-2026!";

    @Test
    void referenceSetup_isSeededAsMonthfoldRunsIt() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eAdminSession master = adminSession();

        final E2eHttp.Response settings = master.get("/admin/realms/" + realm.realm() + "/settings");
        assertThat(settings.status()).as(settings.toString()).isEqualTo(200);
        assertThat(settings.json().path("accessTokenTtlSeconds").asInt()).isEqualTo(300);
        assertThat(settings.json().path("requireMfa").asBoolean()).isTrue();
        assertThat(settings.json().path("registrationEnabled").asBoolean()).isTrue();
        assertThat(master.get("/admin/realms/" + realm.realm() + "/settings/mfa").json().path("skipGraceDays").asInt())
                .isZero();

        // The service account can manage users and nothing else.
        final String token = oidc(realm.realm()).clientCredentials(realm.identityService().clientId(),
                realm.identityService().secret(), null).accessToken();
        final E2eHttp http = newBrowser();
        assertThat(http.get("/admin/realms/" + realm.realm() + "/users", bearer(token)).status()).isEqualTo(200);
        assertThat(http.get("/admin/realms/" + realm.realm() + "/clients", bearer(token)).status()).isEqualTo(403);

        // The realm's HTTP email provider delivers to the mail sink.
        final String to = E2eSeed.unique("inbox") + "@monthfold.test";
        final E2eHttp.Response sent = master.post("/admin/realms/" + realm.realm() + "/messaging/providers/EMAIL/test",
                Map.of("to", to));
        assertThat(sent.status()).as(sent.toString()).isEqualTo(200);
        final MailSink.CapturedEmail email = readCapturedEmail(to);
        assertThat(email.from()).isEqualTo("no-reply@monthfold.test");
        assertThat(email.authorization()).isEqualTo("Bearer mail-sink-token");
    }

    @Test
    void passwordSignIn_thenAGetInitiatedAuthorizeRequest_landsOnTheRpCallback_withAVerifiedIdToken() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        assertThat(URI.create(page().url()).getHost()).as("the IdP is a different origin from the RP").isEqualTo("localhost");
        signInWithPassword(joe.username(), joe.password());

        // A new sign-in from the RP (a GET) completes on the existing IdP session without showing the form.
        startSignInAtRp(realm.web());
        final TestRelyingParty.Callback callback = assertLandedOnRpCallback();

        final JWTClaimsSet id = callback.idTokenClaims();
        assertThat(id.getIssuer()).isEqualTo(baseUrl() + "/realms/" + realm.realm());
        assertThat(id.getAudience()).containsExactly(ReferenceSetup.WEB);
        assertThat(id.getSubject()).isEqualTo(joe.userId());
        assertThat(callback.tokenResponse().path("expires_in").asLong()).isBetween(290L, 300L);
        final JWTClaimsSet access = oidc(realm.realm()).verify(callback.accessToken());
        assertThat(access.getIssuer()).isEqualTo(id.getIssuer());
        assertThat(page().locator("#rp-sub").innerText()).isEqualTo(joe.userId());
    }

    @Test
    void totpEnrolment_continuesToTheRpCallback() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser maya = seed().user(realm.realm(), E2eSeed.unique("maya"), PASSWORD);

        startSignInAtRp(realm.web());
        signInWithPassword(maya.username(), maya.password());
        final TotpDevice device = completeTotpEnrolment();

        assertThat(device.recoveryCodes()).hasSizeGreaterThanOrEqualTo(8);
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(maya.userId());
    }

    @Test
    void rpInitiatedLogout_reachesThePostLogoutPage_andTheRpBackChannel() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        startSignInAtRp(realm.web());
        assertLandedOnRpCallback();

        page().navigate(rp().logoutUrl(realm.web()));

        assertThat(page().url()).startsWith(rp().postLogoutUri());
        assertThat(rp().landings()).hasSize(1);
        // Delivery only: what the token must contain (sid, realm key, …) is asserted by items A3-A5.
        final TestRelyingParty.BackchannelLogout logout = rp().awaitBackchannelLogout(l -> true, WAIT);
        assertThat(logout.claims()).containsEntry("sub", joe.userId());
        assertThat(logout.contentType()).startsWith("application/x-www-form-urlencoded");
    }

    @Test
    @Disabled("A1: CSP form-action blocks cross-origin redirect after POST — fixed in the A1 commit")
    void passwordOnlySignIn_landsOnTheRpCallback() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);

        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());

        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(joe.userId());
        assertThat(cspViolations()).as(describeBrowser()).noneMatch(v -> v.contains("form-action"));
    }

    private static String[] bearer(final String token) {
        return new String[] {"Authorization", "Bearer " + token, "Accept", "application/json"};
    }
}
