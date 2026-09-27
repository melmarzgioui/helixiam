/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A sign-in that starts at {@code /realms/{realm}/login} itself, with no application waiting for it. It used to end
 * at {@code sp.base.url} (the admin console, another origin), which the login and code pages' CSP
 * {@code form-action 'self'} blocked: the browser stayed on the login page.
 *
 * <ul>
 *   <li>A realm other than master: the user lands on the realm's account console, with or without the two-step code.</li>
 *   <li>Master: the operator lands on the admin console ({@code sp.base.url}), whose origin the login and code pages
 *       now allow in {@code form-action}.</li>
 *   <li>The admin console's own OIDC sign-in ({@code helix-console}) still returns to its callback.</li>
 * </ul>
 * Nothing runs at the admin console's addresses here ({@code http://localhost:8090} = {@code sp.base.url},
 * {@code http://localhost:8180} = the console client's base URL): the test checks that the browser went there.
 */
class DirectSignInBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Direct-Sign-In-Passw0rd-2026!";
    private static final String CONSOLE = "http://localhost:8090";
    private static final String CONSOLE_CLIENT_BASE = "http://localhost:8180";

    private final List<String> consoleHits = new CopyOnWriteArrayList<>();

    /**
     * Records every request the browser makes to the consoles. Nothing listens there: a request that is made at all
     * means the page's CSP let the redirect through (a blocked form redirect never leaves the browser).
     */
    @BeforeEach
    void watchConsoles() {
        page().onRequest(r -> {
            if (r.url().startsWith(CONSOLE + "/") || r.url().startsWith(CONSOLE_CLIENT_BASE + "/")) {
                consoleHits.add(r.url());
            }
        });
    }

    private void awaitConsoleRequest(final String prefix) {
        final long deadline = System.currentTimeMillis() + 10_000;
        while (consoleHits.stream().noneMatch(u -> u.startsWith(prefix)) && System.currentTimeMillis() < deadline) {
            page().waitForTimeout(100);
        }
        assertThat(consoleHits).as(describeBrowser()).anyMatch(u -> u.startsWith(prefix));
    }

    @Test
    void aDirectSignIn_inARealm_landsOnItsAccountConsole() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        page().navigate(baseUrl() + realm.path() + "/login");
        signInWithPassword(ada.username(), PASSWORD);

        assertThat(page().url()).as(describeBrowser()).isEqualTo(baseUrl() + realm.path() + "/account");
        assertThat(page().locator("h1").innerText()).as(describeBrowser()).isNotBlank();
        assertThat(consoleHits).as("never the admin console").isEmpty();
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void aDirectSignIn_withTheTwoStepCode_landsOnTheAccountConsoleToo() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.reference());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        page().navigate(baseUrl() + realm.path() + "/login");
        signInWithPassword(ada.username(), PASSWORD);
        final TotpDevice device = completeTotpEnrolment();
        assertThat(page().url()).as("after enrolment\n" + describeBrowser())
                .isEqualTo(baseUrl() + realm.path() + "/account");

        clearCookies();
        page().navigate(baseUrl() + realm.path() + "/login");
        signInWithPassword(ada.username(), PASSWORD);
        enterTotp(device);
        assertThat(page().url()).as("after the code\n" + describeBrowser())
                .isEqualTo(baseUrl() + realm.path() + "/account");
        assertThat(consoleHits).as("never the admin console").isEmpty();
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void aDirectSignIn_inMaster_landsOnTheAdminConsole() {
        page().navigate(baseUrl() + "/realms/master/login");
        signInWithPassword(AbstractE2eTest.ADMIN_USERNAME, AbstractE2eTest.ADMIN_PASSWORD);

        awaitConsoleRequest(CONSOLE + "/");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void theAdminConsolesOwnOidcSignIn_stillReturnsToItsCallback() throws Exception {
        final String verifier = "v".repeat(20) + E2eSeed.unique("pkce").replaceAll("[^A-Za-z0-9]", "") + "v".repeat(20);
        final String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        final String callback = CONSOLE_CLIENT_BASE + "/console/callback";
        page().navigate(baseUrl() + "/realms/master/oauth2/authorize?response_type=code&client_id=helix-console"
                + "&scope=openid&state=s1&code_challenge_method=S256&code_challenge=" + challenge
                + "&redirect_uri=" + URLEncoder.encode(callback, StandardCharsets.UTF_8));
        signInWithPassword(AbstractE2eTest.ADMIN_USERNAME, AbstractE2eTest.ADMIN_PASSWORD);

        awaitConsoleRequest(callback + "?code=");
        assertThat(consoleHits).anyMatch(u -> u.startsWith(callback + "?code=") && u.contains("state=s1"));
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }
}
