/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Response;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Item A6 in a real browser: starting at the relying party, every IdP page a user can reach (login, and by GET from it
 * register, password reset, the language switcher, …; then the two-step enrolment and recovery-code pages after a
 * sign-in) is crawled. Every link, form, script, stylesheet and image the page carries, and every request the
 * browser makes to the IdP, must stay under {@code /realms/{realm}/}, and every crawled page must load (no 4xx/5xx).
 * The template-level check of every template is {@code RealmRelativeLinksTest}.
 */
class RealmLinksCrawlBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Crawl-Links-Passw0rd!";
    /** Collects every URL-bearing attribute of the current document, resolved against it. */
    private static final String COLLECT = "() => Array.from(document.querySelectorAll("
            + "'[href],[src],[action],[formaction],[data-href],[srcset]')).flatMap(e => "
            + "['href','src','action','formaction','data-href'].filter(a => e.hasAttribute(a))"
            + ".map(a => a + '=' + e.getAttribute(a) + ' -> ' + new URL(e.getAttribute(a), document.baseURI).href))";

    @Test
    void everyPageReachableFromTheLoginPage_andTheEnrolmentPages_linkOnlyInsideTheRealm() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final String realmPrefix = baseUrl() + realm.path() + "/";
        final List<String> requests = new CopyOnWriteArrayList<>();
        page().onRequest(r -> requests.add(r.url()));
        final List<String> failed = new CopyOnWriteArrayList<>();
        page().onResponse(r -> {
            if (r.status() >= 400) {
                failed.add(r.status() + " " + r.url());
            }
        });

        startSignInAtRp(realm.web());
        assertOnIdpPath("/login");
        final String login = page().url();

        final List<String> offenders = new ArrayList<>();
        final Set<String> visited = new LinkedHashSet<>();
        final Deque<String> queue = new ArrayDeque<>(List.of(login));
        while (!queue.isEmpty() && visited.size() < 25) {
            final String url = queue.poll();
            if (!visited.add(withoutFragment(url))) {
                continue;
            }
            final Response response = page().navigate(url);
            assertThat(response.status()).as("GET " + url + "\n" + describeBrowser()).isLessThan(400);
            for (final String link : collectLinks(offenders, realmPrefix)) {
                if (link.startsWith(realmPrefix) && crawlable(link)) {
                    queue.add(link);
                }
            }
        }
        assertThat(visited).as("pages crawled").anyMatch(u -> u.contains("/register"))
                .anyMatch(u -> u.contains("/reset/password"));

        // Mid-flow pages: sign in (the pending authorization request is still in the session), enrol the second
        // factor and look at every page on the way back to the app.
        page().navigate(rp().loginUrl(realm.web()));
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        signInWithPassword(ada.username(), ada.password());
        assertOnIdpPath("/mfa/enable");
        collectLinks(offenders, realmPrefix);
        final TotpDevice device = new TotpDevice(page().locator("pre code").first().innerText().trim());
        page().locator("form:has(#code) #code").fill(device.nextCode());
        submit(page().locator("form:has(#code) button[type=submit]"));
        // The recovery codes are the response to the enrolment POST (same URL).
        assertThat(page().locator("ul.recoveryCodes code").count()).as(describeBrowser()).isGreaterThan(0);
        collectLinks(offenders, realmPrefix);
        submit(page().locator(".buttonHolder a.button"));
        assertLandedOnRpCallback();

        assertThat(offenders).as("IdP links outside " + realmPrefix).isEmpty();
        final String idp = baseUrl() + "/";
        assertThat(requests.stream().filter(r -> r.startsWith(idp) && !r.startsWith(realmPrefix)).toList())
                .as("browser requests to the IdP outside the realm").isEmpty();
        assertThat(failed).as("failed requests (pages, scripts, stylesheets, fonts, images)").isEmpty();
    }

    /** The resolved links of the current page; IdP-origin links outside the realm are added to {@code offenders}. */
    @SuppressWarnings("unchecked")
    private List<String> collectLinks(final List<String> offenders, final String realmPrefix) {
        final List<String> found = (List<String>) page().evaluate(COLLECT);
        final List<String> resolved = new ArrayList<>();
        final String idp = baseUrl() + "/";
        for (final String entry : found) {
            final String absolute = entry.substring(entry.indexOf(" -> ") + 4);
            resolved.add(absolute);
            if (absolute.startsWith(idp) && !absolute.startsWith(realmPrefix)) {
                offenders.add(page().url() + ": " + entry);
            }
        }
        return resolved;
    }

    /** Pages to follow: realm pages by GET, never protocol endpoints, federation or static files. */
    private static boolean crawlable(final String url) {
        final String path = URI.create(url).getPath();
        return !(path.contains("/oauth2/") || path.contains("/connect/") || path.contains("/broker/")
                || path.contains("/logout") || path.contains("/css/") || path.contains("/js/") || path.contains("/img/")
                || path.contains("/theme") || path.contains("/fonts/"));
    }

    private static String withoutFragment(final String url) {
        final int hash = url.indexOf('#');
        return hash < 0 ? url : url.substring(0, hash);
    }
}
