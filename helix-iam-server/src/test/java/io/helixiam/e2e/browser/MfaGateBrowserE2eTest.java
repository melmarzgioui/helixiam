/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two-step gate in front of {@code /oauth2/authorize} ({@code MfaEnforcementFilter}): in a realm that requires
 * a second factor, no authorization code is issued to a browser session that has not completed one, whichever way
 * the session was established or the request arrives. Each test drives a real browser against the reference realm
 * and a relying party on another origin, and fails if the RP receives a code.
 */
class MfaGateBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Mfa-Gate-Passw0rd-2026!";

    /**
     * A session that signed in with a password while the realm did not require a second factor is a full session. When
     * the realm then requires one, the next authorization request (silent SSO from the app) must go through the
     * second step: the gate is the only thing between that session and a code.
     */
    @Test
    void aPasswordOnlySession_fromBeforeTheRealmRequiredMfa_getsNoCode_andIsSentToEnrolment() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        assertLandedOnRpCallback();
        rp().reset();

        requireMfa(realm);
        startSignInAtRp(realm.web());

        assertNoCode("silent SSO on a password-only session after requireMfa");
        assertOnIdpPath("/mfa/enable");
        // Completing enrolment resumes the request and only then issues the code.
        final TotpDevice device = completeTotpEnrolment();
        assertThat(device.recoveryCodes()).isNotEmpty();
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(joe.userId());
    }

    /** Same session, {@code prompt=none}: no code and no page — the RP gets an error instead. */
    @Test
    void aPasswordOnlySession_withPromptNone_getsNoCode() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        assertLandedOnRpCallback();
        rp().reset();

        requireMfa(realm);
        startSignInAtRp(realm.web(), Map.of("prompt", "none"));

        assertNoCode("prompt=none on a password-only session after requireMfa");
        final TestRelyingParty.Callback callback = rpLastCallback().orElseThrow(() -> new AssertionError(describeBrowser()));
        assertThat(callback.params()).as(describeBrowser()).containsEntry("error", "interaction_required")
                .containsKey("state");
    }

    /** Mid-enrolment (password done, TOTP not): a direct GET to the authorization endpoint issues no code. */
    @Test
    void midEnrolment_aDirectAuthorizeRequest_getsNoCode() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        assertOnIdpPath("/mfa/enable");

        startSignInAtRp(realm.web());
        assertNoCode("a fresh authorize request mid-enrolment");
        startSignInAtRp(realm.web(), Map.of("prompt", "none"));
        assertNoCode("prompt=none mid-enrolment");
    }

    /** Mid-code (enrolled user, password done, code not entered): a second client in the session gets no code. */
    @Test
    void midCode_aSecondClientInTheSession_getsNoCode() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        completeTotpEnrolment();
        assertLandedOnRpCallback();
        clearCookies();
        rp().reset();

        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        assertOnIdpPath("/mfa/totp");
        final E2eSeed.SeededClient other = seed().confidentialClient(realm.realm(), E2eSeed.unique("other"),
                java.util.List.of("openid"));
        page().navigate(baseUrl() + realm.path() + "/oauth2/authorize?response_type=code&client_id=" + other.clientId()
                + "&scope=openid&redirect_uri=" + java.net.URLEncoder.encode(other.redirectUri(),
                java.nio.charset.StandardCharsets.UTF_8) + "&state=s1");
        assertThat(page().url()).as(describeBrowser()).doesNotContain("code=");
        assertNoCode("the RP while another client asked mid-code");
    }

    /** {@code prompt=login} re-authentication with the password only must again ask for the second factor. */
    @Test
    void promptLogin_reAuthentication_asksForTheSecondFactorAgain() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        final TotpDevice device = completeTotpEnrolment();
        assertLandedOnRpCallback();
        rp().reset();

        startSignInAtRp(realm.web(), Map.of("prompt", "login"));
        signInWithPassword(joe.username(), joe.password());
        assertNoCode("prompt=login after the password only");
        assertOnIdpPath("/mfa/totp");
        enterTotp(device);
        assertLandedOnRpCallback();
    }

    /** A magic link is a first factor: in a realm that requires two, it leads to the second step, not a code. */
    @Test
    void aMagicLink_isOnlyTheFirstFactor() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eHttp.Response magic = adminSession().put("/admin/realms/" + realm.realm() + "/settings/magic-link",
                Map.of("enabled", true));
        assertThat(magic.status()).as(magic.toString()).isEqualTo(200);
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);

        startSignInAtRp(realm.web());
        submit(page().locator("a.magicLink"));
        assertOnIdpPath("/login/magic");
        page().locator("#email").fill(joe.dto().email());
        submit(page().locator("form button[type=submit]"));
        final String link = io.helixiam.e2e.CapturingMagicLinkSender.linksFor(joe.dto().email()).get(0);
        page().navigate(link);
        submit(page().locator("form button[type=submit]"));

        assertNoCode("magic link in a requireMfa realm");
        assertOnIdpPath("/mfa/enable");
    }

    /**
     * Federated sign-in: after the upstream identity provider authenticated the user, the realm's post-broker flow
     * completes (it has no second-factor step for a user without one) and a full session resumes the authorization
     * request. In a realm that requires a second factor, the gate must send the user to enrolment first.
     */
    @Test
    void aFederatedSignIn_inARequireMfaRealm_getsNoCode_untilTheSecondFactor() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + ada.userId());

        assertNoCode("a federated sign-in in a requireMfa realm");
        assertOnIdpPath("/mfa/enable");
        completeTotpEnrolment();
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(ada.userId());
    }

    // ------------------------------------------------------------------------------------------------

    private void requireMfa(final ReferenceSetup.Realm realm) {
        final E2eHttp.Response r = adminSession().put("/admin/realms/" + realm.realm() + "/settings/mfa",
                Map.of("requireMfa", true, "skipGraceDays", 0));
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
    }

    private void assertNoCode(final String what) {
        assertThat(rp().callbacks().stream().filter(c -> c.code() != null).toList())
                .as(what + ": the RP must not receive an authorization code\n" + describeBrowser()).isEmpty();
        if (onRpOrigin()) {
            assertThat(URI.create(page().url()).getQuery()).as(what).doesNotContain("code=");
        }
    }
}
