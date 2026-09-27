/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Page;
import com.microsoft.playwright.Response;
import com.microsoft.playwright.options.ColorScheme;
import io.helixiam.e2e.E2eHttp;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item 6: an OAuth / OIDC error that cannot go back to the application (an unknown {@code client_id}, a redirect URI
 * that is not registered, a request without {@code client_id}, a bare {@code GET /connect/logout}) ends on a page in
 * the realm's theme: the shared theme fragment with the realm's stylesheet, a clear message, no stack trace, no
 * Spring "Whitelabel" page, nothing from the request echoed, and no CSP violation (no inline style or script). An API
 * client that does not ask for HTML still gets JSON. The front-channel logout page is themed too.
 *
 * <p>With {@code -Dhelix.shots=<dir>} the pages are also captured in light and dark mode at 1440 and 390 px wide.
 */
class ProtocolErrorPagesBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PROBE = "zz<b>probe</b>\"'";
    private static final String SURFACE = "#f7f8f6";

    private static Map<String, Object> theme() {
        return Map.of("colors", Map.of("primary", Map.of("light", "#1f4d47", "dark", "#7fb8ac"),
                        "surface", Map.of("light", SURFACE, "dark", "#111615"),
                        "surfaceRaised", Map.of("light", "#ffffff", "dark", "#192120"),
                        "ink", Map.of("light", "#16211f", "dark", "#e8eeec"),
                        "inkMuted", Map.of("light", "#56635f", "dark", "#a3b0ac")),
                "texts", Map.of("footerText", "© Monthfold BV, Utrecht"));
    }

    @Test
    void protocolErrors_endOnAThemedPage_withoutEchoingTheRequest() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        assertThat(adminSession().put("/admin/realms/" + realm.realm() + "/theme", theme()).status()).isEqualTo(200);
        final String authorize = baseUrl() + realm.path() + "/oauth2/authorize?response_type=code&scope=openid"
                + "&state=" + enc(PROBE);

        final Map<String, String> cases = new java.util.LinkedHashMap<>();
        cases.put("unknown-client", authorize + "&client_id=" + enc("nope-" + PROBE)
                + "&redirect_uri=" + enc(rp().callbackUri()));
        cases.put("unregistered-redirect", authorize + "&client_id=" + ReferenceSetup.WEB
                + "&redirect_uri=" + enc("https://evil.example/cb?" + PROBE));
        cases.put("no-client-id", authorize);
        cases.put("bare-logout", baseUrl() + realm.path() + "/connect/logout");
        // S3: title, lead and way back per kind; the way back is always a page of the realm (B2).
        final Map<String, List<String>> expected = Map.of(
                "unknown-client", List.of("Unknown application", "The application that sent you here is not known",
                        "/account", "Go to your account"),
                "unregistered-redirect", List.of("Return address not allowed", "an address that is not registered for it",
                        "/account", "Go to your account"),
                "no-client-id", List.of("Incomplete sign-in request", "The sign-in request is incomplete or invalid",
                        "/account", "Go to your account"),
                "bare-logout", List.of("You could not be signed out here", "This sign-out link is incomplete",
                        "/login", "Back to sign in"),
                "not-found", List.of("Page not found", "This page does not exist", "/account", "Go to your account"));

        // 404: a page that does not exist, for a signed-in user (anyone else is sent to sign in first).
        final io.helixiam.e2e.E2eSeed.SeededUser ada = seed().user(realm.realm(),
                io.helixiam.e2e.E2eSeed.unique("ada"), "Error-Pages-Passw0rd-2026!");
        startSignInAtRp(realm.web());
        signInWithPassword(ada.username(), "Error-Pages-Passw0rd-2026!");
        assertLandedOnRpCallback();
        cases.put("not-found", baseUrl() + realm.path() + "/no-such-page");

        for (final Map.Entry<String, String> c : cases.entrySet()) {
            final Response response = page().navigate(c.getValue());
            final String which = c.getKey();
            final List<String> want = expected.get(which);
            assertThat(response.status()).as(which + "\n" + describeBrowser())
                    .isEqualTo("not-found".equals(which) ? 404 : 400);
            assertThat(response.headerValue("content-type")).as(which).startsWith("text/html");
            assertThemedErrorPage(realm, which);
            assertThat(page().locator("h1").innerText()).as(which).isEqualTo(want.get(0));
            assertThat(page().locator("main").innerText()).as(which).contains(want.get(1));
            assertWayBack(realm, which, want.get(2), want.get(3));
            assertTechnicalDetails(which, !"not-found".equals(which));
            shots(which);
        }

        // 403: a sign-in form posted without its CSRF token.
        clearCookies();
        page().navigate(baseUrl() + realm.path() + "/login");
        final Response forbidden = page().waitForNavigation(() -> page().evaluate("() => { const f = "
                + "document.createElement('form'); f.method = 'post'; f.action = location.pathname; "
                + "document.body.appendChild(f); f.submit(); }"));
        assertThat(forbidden.status()).as(describeBrowser()).isEqualTo(403);
        assertThemedErrorPage(realm, "forbidden");
        assertThat(page().locator("h1").innerText()).isEqualTo("Access denied");
        assertWayBack(realm, "forbidden", "/login", "Back to sign in");
        shots("forbidden");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void inDutch_theErrorPageIsDutch() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        page().navigate(baseUrl() + realm.path() + "/login?lang=nl");
        final Response response = page().navigate(baseUrl() + realm.path() + "/oauth2/authorize?response_type=code"
                + "&client_id=nope&scope=openid&redirect_uri=" + enc(rp().callbackUri()));
        assertThat(response.status()).isEqualTo(400);
        assertThat(page().locator("html").getAttribute("lang")).isEqualTo("nl");
        assertThat(page().locator("main").innerText()).contains("is niet bekend").doesNotContain("not known");
        assertThat(page().locator("h1").innerText()).isEqualTo("Onbekende applicatie");
        assertThat(page().locator("main a.hx-back").innerText()).isEqualTo("Naar je account");
        assertThat(page().locator("details summary").innerText()).isEqualTo("Technische details");
    }

    @Test
    void apiClients_stillGetJson() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eHttp http = newBrowser();
        final E2eHttp.Response json = http.get(realm.path() + "/oauth2/authorize?response_type=code&client_id=nope"
                + "&scope=openid&redirect_uri=" + enc(rp().callbackUri()), "Accept", "application/json");
        assertThat(json.status()).isEqualTo(400);
        assertThat(json.header("Content-Type").orElse("")).startsWith("application/json");
        assertThat(json.body()).contains("\"status\":400").doesNotContain("<html");

        final E2eHttp.Response logout = http.get(realm.path() + "/connect/logout", "Accept", "*/*");
        assertThat(logout.status()).isEqualTo(400);
        assertThat(logout.body()).doesNotContain("<html");
    }

    @Test
    void theFrontChannelLogoutPage_isThemed_andLoadsTheClientsLogoutUrls() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        assertThat(adminSession().put("/admin/realms/" + realm.realm() + "/theme", theme()).status()).isEqualTo(200);
        final String frontchannel = rp().origin() + "/auth/frontchannel-logout";
        final io.helixiam.authorization.amqp.client.ClientDto portal = context.getBean(
                io.helixiam.authorization.amqp.client.ClientAdminPublisher.class).create(
                new io.helixiam.authorization.amqp.client.ClientWriteDto(realm.realm(), null, "portal",
                        List.of("authorization_code", "refresh_token"), List.of(rp().callbackUri()),
                        List.of("openid", "profile", "email"), null, null, "Portal", null, List.of(rp().postLogoutUri()),
                        List.of(rp().origin()), false, false, true, null, null, null, null, false,
                        null, null, null, false, "client_secret_basic", null,
                        null, frontchannel, null, false, false, null));
        final TestRelyingParty.Client client = rp().register(realm.realm(), "portal", portal.secret(),
                ReferenceSetup.SCOPE);

        final io.helixiam.e2e.E2eSeed.SeededUser ada = seed().user(realm.realm(),
                io.helixiam.e2e.E2eSeed.unique("ada"), "Front-Channel-Passw0rd-2026!");
        startSignInAtRp(client);
        signInWithPassword(ada.username(), "Front-Channel-Passw0rd-2026!");
        final TestRelyingParty.Callback callback = assertLandedOnRpCallback();

        final List<String> frames = new java.util.concurrent.CopyOnWriteArrayList<>();
        page().onRequest(r -> {
            if (r.url().startsWith(frontchannel)) {
                frames.add(r.url());
            }
        });
        page().navigate(baseUrl() + realm.path() + "/connect/logout?id_token_hint=" + enc(callback.idToken())
                + "&post_logout_redirect_uri=" + enc(rp().postLogoutUri()) + "&client_id=portal",
                new Page.NavigateOptions().setWaitUntil(com.microsoft.playwright.options.WaitUntilState.DOMCONTENTLOADED));
        assertThat(page().locator("main").innerText()).contains("Signing you out");
        // S4: the status is announced, the delay stated, and the button has context.
        assertThat(page().locator("[role=status]").innerText()).contains("every app you used").contains("2 seconds");
        assertThat(page().locator("main article").innerText()).contains("Not taken on?");
        assertThemedPage(realm, "front-channel logout");
        shots("frontchannel-logout");
        page().waitForURL(u -> u.startsWith(rp().postLogoutUri()), new Page.WaitForURLOptions().setTimeout(10_000));
        assertThat(frames).as("the client's front-channel logout URL").isNotEmpty();
        assertThat(frames.get(0)).contains("iss=").contains("sid=");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    /** B2: a way back to a page of the realm, and no link to anything the request named. */
    @Test
    void rpLogout_withoutAPostLogoutUri_endsOnTheRealmsThemedSignedOutPage() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        assertThat(adminSession().put("/admin/realms/" + realm.realm() + "/theme", theme()).status()).isEqualTo(200);
        final io.helixiam.e2e.E2eSeed.SeededUser ada = seed().user(realm.realm(),
                io.helixiam.e2e.E2eSeed.unique("ada"), "Signed-Out-Passw0rd-2026!");
        startSignInAtRp(realm.web());
        signInWithPassword(ada.username(), "Signed-Out-Passw0rd-2026!");
        final TestRelyingParty.Callback callback = assertLandedOnRpCallback();

        final Response response = page().navigate(baseUrl() + realm.path() + "/connect/logout?id_token_hint="
                + enc(callback.idToken()));
        assertThat(response.status()).as(describeBrowser()).isEqualTo(200);
        assertThat(page().url()).isEqualTo(baseUrl() + realm.path() + "/signed-out");
        assertThat(page().locator("h1").innerText()).isEqualTo("You're signed out");
        assertThemedPage(realm, "signed out");
        assertWayBack(realm, "signed out", "/login", "Sign in again");
        assertThat(page().locator("nav.lang").count()).as("the language switcher").isEqualTo(1);
        shots("signed-out");

        page().navigate(baseUrl() + realm.path() + "/signed-out?lang=nl");
        assertThat(page().locator("h1").innerText()).isEqualTo("Je bent uitgelogd");
        page().navigate(baseUrl() + realm.path() + "/signed-out?lang=en");
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    private void assertWayBack(final ReferenceSetup.Realm realm, final String which, final String path,
                               final String label) {
        final com.microsoft.playwright.Locator back = page().locator("main a.hx-back");
        assertThat(back.count()).as(which + ": one way back").isEqualTo(1);
        assertThat(back.getAttribute("href")).as(which).isEqualTo(realm.path() + path);
        assertThat(back.innerText()).as(which).isEqualTo(label);
        for (final Object href : (List<?>) page().evaluate("() => [...document.querySelectorAll('a[href]')].map(a => a.href)")) {
            assertThat(String.valueOf(href)).as(which + ": links stay on this server")
                    .startsWith(baseUrl()).doesNotContain("evil.example");
        }
    }

    /**
     * S1/S2: the OAuth code only inside a closed "Technical details"; the reference small and monospace; the card's
     * paragraphs spaced by the card, not by their own margins.
     */
    private void assertTechnicalDetails(final String which, final boolean withCode) {
        final com.microsoft.playwright.Locator details = page().locator("main details.hx-details");
        if (withCode) {
            assertThat(details.getAttribute("open")).as(which).isNull();
            assertThat(details.locator("summary").innerText()).as(which).isEqualTo("Technical details");
            assertThat(details.textContent()).as(which).contains("invalid_request");
            String outside = page().locator("main").innerText();
            assertThat(outside).as(which + ": the code is not in the page text").doesNotContain("invalid_request");
        } else {
            assertThat(details.count()).as(which).isZero();
        }
        final com.microsoft.playwright.Locator reference = page().locator("main .hx-reference");
        assertThat(reference.innerText()).as(which).startsWith("Reference: ");
        final String refFont = String.valueOf(page().evaluate(
                "() => getComputedStyle(document.querySelector('main .hx-reference code')).fontFamily"));
        final String bodyFont = String.valueOf(page().evaluate("() => getComputedStyle(document.body).fontFamily"));
        assertThat(refFont).as(which + ": monospace reference").isNotEqualTo(bodyFont);
        final double refSize = Double.parseDouble(String.valueOf(page().evaluate(
                "() => parseFloat(getComputedStyle(document.querySelector('main .hx-reference')).fontSize)")));
        final double bodySize = Double.parseDouble(String.valueOf(page().evaluate(
                "() => parseFloat(getComputedStyle(document.querySelector('main article')).fontSize)")));
        assertThat(refSize).as(which + ": small reference").isLessThan(bodySize);
        assertThat(page().evaluate("() => getComputedStyle(document.querySelector('main .hx-reference span')).color"))
                .as(which + ": the reference is muted like the lead")
                .isEqualTo(page().evaluate("() => getComputedStyle(document.querySelector('main .hx-lead')).color"));
        final double labelSize = Double.parseDouble(String.valueOf(page().evaluate(
                "() => parseFloat(getComputedStyle(document.querySelector('main .hx-reference span')).fontSize)")));
        assertThat(labelSize).as(which + ": the whole reference line is small").isEqualTo(refSize);
        assertThat(page().evaluate("() => [...document.querySelectorAll('main article > p')]"
                + ".every(p => getComputedStyle(p).marginTop === '0px' && getComputedStyle(p).marginBottom === '0px')"))
                .as(which + ": no paragraph margins in the card").isEqualTo(true);
    }

    private void assertThemedErrorPage(final ReferenceSetup.Realm realm, final String which) {
        assertThemedPage(realm, which);
        final String html = page().content();
        assertThat(html).as(which + ": no stack trace or Spring page").doesNotContain("Whitelabel")
                .doesNotContain("Exception").doesNotContain("at org.").doesNotContain("at io.helixiam")
                .doesNotContain("OAuth 2.0 Parameter");
        assertThat(html).as(which + ": nothing from the request").doesNotContain("probe").doesNotContain("evil.example")
                .doesNotContain("nope");
        assertThat(page().locator("h1").innerText()).as(which).isNotBlank();
    }

    private void assertThemedPage(final ReferenceSetup.Realm realm, final String which) {
        assertThat(page().locator("link.hx-theme").getAttribute("href")).as(which + ": the realm's theme stylesheet")
                .startsWith(realm.path() + "/theme.css");
        final Object background = page().evaluate("getComputedStyle(document.body).backgroundColor");
        assertThat(String.valueOf(background)).as(which + ": the theme's surface colour").isEqualTo("rgb(247, 248, 246)");
        assertThat(page().locator("footer").innerText()).as(which).contains("© Monthfold BV, Utrecht");
        assertThat(page().locator("[style]").count()).as(which + ": no inline style").isZero();
        assertThat(page().locator("script:not([src])").count()).as(which + ": no inline script").isZero();
    }

    /** Light and dark at 1440 and 390 px into {@code -Dhelix.shots}, when set. */
    private void shots(final String name) {
        final String dir = System.getProperty("helix.shots");
        if (dir == null || dir.isBlank()) {
            return;
        }
        for (final ColorScheme scheme : List.of(ColorScheme.LIGHT, ColorScheme.DARK)) {
            for (final int width : List.of(1440, 390)) {
                page().emulateMedia(new Page.EmulateMediaOptions().setColorScheme(scheme));
                page().setViewportSize(width, width == 390 ? 844 : 900);
                page().screenshot(new Page.ScreenshotOptions().setFullPage(true).setPath(Path.of(dir,
                        name + "-" + scheme.name().toLowerCase(java.util.Locale.ROOT) + "-" + width + ".png")));
            }
        }
        page().emulateMedia(new Page.EmulateMediaOptions().setColorScheme(ColorScheme.LIGHT));
        page().setViewportSize(1280, 900);
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
