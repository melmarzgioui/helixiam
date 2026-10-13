/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.options.Cookie;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security: a federated login (post-broker, the real {@link io.helixiam.authorization.federation.FederatedLoginCompleter}
 * reached through the test-only {@link io.helixiam.e2e.FederatedLoginStubController}) must rotate the HTTP
 * session id before establishing the full session — otherwise a session id an attacker already knows (e.g.
 * fixed via a crafted link before the federated hand-off) survives sign-in. Drives a real browser so the
 * assertion covers the actual {@code SESSION} cookie Spring Session issues, not just the servlet request.
 */
class FederatedSessionRotationBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Federated-Rotation-Passw0rd-2026!";

    @Test
    void federatedSignIn_rotatesTheSessionCookie() {
        // No MFA: the post-broker flow COMPLETES immediately, so this exercises FederatedLoginCompleter's own
        // rotation directly (the step-up path is covered separately in FlowControllerTest).
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        final String before = sessionCookieValue()
                .orElseThrow(() -> new AssertionError("no SESSION cookie before federation\n" + describeBrowser()));

        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + ada.userId());

        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(ada.userId());
        final String after = sessionCookieValue()
                .orElseThrow(() -> new AssertionError("no SESSION cookie after federation\n" + describeBrowser()));
        assertThat(after).as("the session cookie must rotate on federated login\n" + describeBrowser())
                .isNotEqualTo(before);
    }

    /**
     * Security (code review follow-up): Redis and Spring-JDBC rename a session's row in place when
     * {@code request.changeSessionId()} runs, but the queue (PostgreSQL) store keys rows by id — a save after
     * rotation must explicitly delete the pre-rotation row, or replaying its cookie resurrects a session an
     * attacker could have captured before a step-up/re-authentication, with logout of the NEW id never ending it.
     * Covers the specific leak scenario: an ALREADY authenticated session re-authenticates through the broker
     * (e.g. {@code prompt=login}) and rotates a second time on top of a fully authenticated context.
     */
    @Test
    void reAuthenticatingThroughTheBroker_invalidatesThePreRotationSessionRow() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        startSignInAtRp(realm.web());
        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + ada.userId());
        assertThat(assertLandedOnRpCallback().subject()).isEqualTo(ada.userId());
        final Cookie firstAuthenticated = sessionCookie();

        // Re-authenticate through the broker again on the same (already fully authenticated) browser: a second
        // rotation on top of an authenticated context, same as a forced re-login / step-up re-auth.
        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + ada.userId());
        final Cookie secondAuthenticated = sessionCookie();
        assertThat(secondAuthenticated.value).as("the second broker hit must rotate again\n" + describeBrowser())
                .isNotEqualTo(firstAuthenticated.value);

        // Replay the FIRST (pre-rotation) authenticated cookie: it must no longer be an authenticated session.
        restoreSessionCookie(firstAuthenticated);
        page().navigate(baseUrl() + realm.path() + "/account/profile");
        assertOnIdpPath("/login");
    }

    private Cookie sessionCookie() {
        return page().context().cookies().stream()
                .filter(c -> "SESSION".equals(c.name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no SESSION cookie\n" + describeBrowser()));
    }

    private void restoreSessionCookie(final Cookie cookie) {
        page().context().addCookies(List.of(cookie));
    }

    private Optional<String> sessionCookieValue() {
        return page().context().cookies().stream()
                .filter(c -> "SESSION".equals(c.name))
                .map(c -> c.value)
                .findFirst();
    }
}
