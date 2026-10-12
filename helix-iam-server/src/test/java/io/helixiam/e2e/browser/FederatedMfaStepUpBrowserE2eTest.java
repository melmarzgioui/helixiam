/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Locator;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Federated sign-in (OIDC, SAML or eID broker) runs the realm's post-broker flow: the built-in browser flow asks for
 * the second factor when the user has one enrolled. The flow's {@code mfa-enabled} condition must answer for the
 * brokered user, although nobody is signed in yet when the flow starts. The stub stands in for the upstream
 * identity provider's callback, after which everything is the real post-broker path.
 */
class FederatedMfaStepUpBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Federated-Step-Up-Passw0rd-2026!";

    /**
     * Ada enrolled an authenticator; the realm itself does not require one, so only her own enrolment asks for the
     * second factor. A brokered sign-in must stop at the code, with no session until the code is right.
     */
    @Test
    void aBrokeredSignIn_ofAUserWithMfa_stopsAtTheSecondFactor_beforeAnySession() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        startSignInAtRp(realm.web());
        signInWithPassword(ada.username(), ada.password());
        final TotpDevice device = completeTotpEnrolment();
        assertLandedOnRpCallback();
        final E2eHttp.Response off = adminSession().put("/admin/realms/" + realm.realm() + "/settings/mfa",
                Map.of("requireMfa", false, "skipGraceDays", 0));
        assertThat(off.status()).as(off.toString()).isEqualTo(200);
        clearCookies();
        rp().reset();

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + ada.userId());

        assertNoCode("a brokered sign-in of a user with a second factor");
        assertOnIdpPath("/flow");
        // No session yet: another authorization request in this browser gets no code either.
        startSignInAtRp(realm.web());
        assertNoCode("a fresh authorization request before the second factor");

        page().navigate(baseUrl() + realm.path() + "/flow");
        final Locator form = page().locator("form:has(#code)");
        form.locator("#code").fill(device.nextCode());
        submit(form.locator("button[type=submit]"));
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(ada.userId());
    }

    /** Without a second factor (and a realm that does not require one) the brokered sign-in completes at once. */
    @Test
    void aBrokeredSignIn_ofAUserWithoutMfa_completes() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser bob = seed().user(realm.realm(), E2eSeed.unique("bob"), PASSWORD);

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + bob.userId());

        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(bob.userId());
    }

    /** Review #2: the session that carried the broker round-trip is not the one that becomes signed in. */
    @Test
    void aBrokeredSignIn_getsANewSessionId() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser bob = seed().user(realm.realm(), E2eSeed.unique("bob"), PASSWORD);
        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        final String before = sessionCookie();

        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + bob.userId());

        assertLandedOnRpCallback();
        assertThat(before).as("a session existed before the broker callback").isNotNull();
        assertThat(sessionCookie()).as("session id after the federated sign-in").isNotNull().isNotEqualTo(before);
    }

    private String sessionCookie() {
        return page().context().cookies(baseUrl()).stream()
                .filter(c -> "SESSION".equals(c.name) || "JSESSIONID".equals(c.name))
                .map(c -> c.value).findFirst().orElse(null);
    }

    private void assertNoCode(final String what) {
        assertThat(rp().callbacks().stream().filter(c -> c.code() != null).toList())
                .as(what + ": the RP must not receive an authorization code\n" + describeBrowser()).isEmpty();
        if (onRpOrigin()) {
            assertThat(URI.create(page().url()).getQuery()).as(what).doesNotContain("code=");
        }
    }
}
