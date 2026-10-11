/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

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

    private Optional<String> sessionCookieValue() {
        return page().context().cookies().stream()
                .filter(c -> "SESSION".equals(c.name))
                .map(c -> c.value)
                .findFirst();
    }
}
