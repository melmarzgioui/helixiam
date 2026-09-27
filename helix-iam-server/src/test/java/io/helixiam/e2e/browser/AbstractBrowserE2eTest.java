/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Locator;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import com.microsoft.playwright.Tracing;
import com.microsoft.playwright.impl.driver.Driver;
import com.microsoft.playwright.options.LoadState;
import io.helixiam.e2e.AbstractE2eTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Base class for REAL-BROWSER end-to-end tests: a headless Chromium (Playwright) drives the embedded IdP of
 * {@link AbstractE2eTest} ({@code http://localhost:<port>}) and a {@link TestRelyingParty} on another origin
 * ({@code http://127.0.0.1:<port>}). Unlike the HTTP-client e2e tests, the browser enforces CSP, cookies,
 * redirects after form posts and JavaScript, so it catches what they cannot (item A1 was invisible to them).
 *
 * <h2>Lifecycle (keep it fast)</h2>
 * <ul>
 *   <li>Per test class: one Chromium process and one {@link TestRelyingParty} ({@code @BeforeAll}).</li>
 *   <li>Per test: a fresh {@link BrowserContext} (empty cookie jar, like a new private window) and one
 *       {@link Page}; console messages, CSP violations, failed requests and the navigation trail are recorded.</li>
 *   <li>On failure: a screenshot, the page HTML, the recorded browser log and a Playwright trace go to
 *       {@code target/browser-failures/<TestClass>/<method>.*} (open the trace with
 *       {@code mvn exec:java -Dexec.mainClass=com.microsoft.playwright.CLI -Dexec.classpathScope=test
 *       -Dexec.args="show-trace target/browser-failures/…zip"}).</li>
 * </ul>
 * The Spring context, database and server are the shared e2e ones: do not add property sources here (see
 * {@link AbstractE2eTest}). The browser, not the harness, must see the same issuer as the RP: both use
 * {@code http://localhost:<port>}, which is also {@code idp.base.url}.
 *
 * <h2>Switches</h2>
 * {@code -Dhelix.e2e.browser=false} skips every browser test (e.g. no network for the one-time Chromium download);
 * {@code -Dhelix.e2e.browser.headed=true} shows the browser while debugging.
 */
@ExtendWith(AbstractBrowserE2eTest.FailureCapture.class)
public abstract class AbstractBrowserE2eTest extends AbstractE2eTest {

    /** How long a helper waits for an email / back-channel call. */
    protected static final Duration WAIT = Duration.ofSeconds(15);

    private static Playwright playwright;
    private static Browser browser;
    private static TestRelyingParty rp;
    private static boolean chromiumInstalled;

    private BrowserContext browserContext;
    private Page page;
    private final List<String> browserLog = new CopyOnWriteArrayList<>();
    private final List<String> cspViolations = new CopyOnWriteArrayList<>();
    private final List<String> navigations = new CopyOnWriteArrayList<>();
    private final List<BrowserContext> otherBrowsers = new CopyOnWriteArrayList<>();

    @BeforeAll
    static void launchBrowserAndRelyingParty() {
        Assumptions.assumeFalse("false".equalsIgnoreCase(System.getProperty("helix.e2e.browser")),
                "browser tests disabled (-Dhelix.e2e.browser=false)");
        installChromiumOnce();
        playwright = Playwright.create(new Playwright.CreateOptions()
                .setEnv(Map.of("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")));
        browser = playwright.chromium().launch(new BrowserType.LaunchOptions()
                .setHeadless(!Boolean.getBoolean("helix.e2e.browser.headed")));
        rp = TestRelyingParty.start(baseUrl());
    }

    /**
     * Downloads Playwright's Chromium (and only Chromium: {@code Playwright.create()} would fetch Firefox and WebKit
     * too) unless already present. A no-op after the first run on a machine; CI caches the download directory.
     */
    private static synchronized void installChromiumOnce() {
        if (chromiumInstalled) {
            return;
        }
        final ProcessBuilder install = Driver.ensureDriverInstalled(Map.of(), false).createProcessBuilder();
        install.command().addAll(List.of("install", "chromium"));
        install.redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.INHERIT);
        try {
            final int exit = install.start().waitFor();
            if (exit != 0) {
                throw new IllegalStateException("playwright install chromium exited with " + exit);
            }
        } catch (final IOException e) {
            throw new UncheckedIOException(e);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
        chromiumInstalled = true;
    }

    @AfterAll
    static void closeBrowserAndRelyingParty() {
        if (rp != null) {
            rp.close();
            rp = null;
        }
        if (browser != null) {
            browser.close();
            browser = null;
        }
        if (playwright != null) {
            playwright.close();
            playwright = null;
        }
    }

    @BeforeEach
    void openPage() {
        rp.reset();
        browserContext = browser.newContext(new Browser.NewContextOptions().setLocale("en-GB")
                .setViewportSize(1280, 900));
        browserContext.tracing().start(new Tracing.StartOptions().setScreenshots(true).setSnapshots(true));
        // Report CSP violations from every document (the event fires in the document that was blocked from
        // navigating/submitting). Console messages carry the same text for form-action on redirects.
        browserContext.exposeBinding("__helixCspViolation", (source, args) -> {
            cspViolations.add(String.valueOf(args[0]));
            return null;
        });
        browserContext.addInitScript("document.addEventListener('securitypolicyviolation', e => "
                + "window.__helixCspViolation(e.violatedDirective + ' blocked ' + e.blockedURI "
                + "+ ' on ' + e.documentURI + ' (' + e.disposition + ')'));");
        page = browserContext.newPage();
        page.setDefaultTimeout(15_000);
        page.setDefaultNavigationTimeout(20_000);
        page.onConsoleMessage(m -> {
            browserLog.add("console." + m.type() + ": " + m.text());
            if (m.text().contains("Content Security Policy")) {
                cspViolations.add(m.text());
            }
        });
        page.onPageError(e -> browserLog.add("pageerror: " + e));
        page.onRequestFailed(r -> browserLog.add("requestfailed: " + r.method() + " " + r.url() + " -> " + r.failure()));
        page.onFrameNavigated(f -> {
            if (f == page.mainFrame()) {
                navigations.add(f.url());
            }
        });
    }

    @AfterEach
    void closePage() {
        otherBrowsers.forEach(BrowserContext::close);
        otherBrowsers.clear();
        if (browserContext != null) {
            try {
                browserContext.tracing().stop();
            } catch (final RuntimeException ignored) {
                // already stopped by the failure capture
            }
            browserContext.close();
            browserContext = null;
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------------------------------------

    /** The current tab. */
    protected Page page() {
        return page;
    }

    /**
     * A tab in another, independent browser (its own cookie jar — another device), for tests with more than one
     * sign-in; closed after the test.
     */
    protected Page otherBrowser() {
        final BrowserContext other = browser.newContext(new Browser.NewContextOptions().setLocale("en-GB")
                .setViewportSize(1280, 900));
        otherBrowsers.add(other);
        final Page tab = other.newPage();
        tab.setDefaultTimeout(15_000);
        tab.setDefaultNavigationTimeout(20_000);
        return tab;
    }

    /** This class's relying party (another origin). */
    protected TestRelyingParty rp() {
        return rp;
    }

    /** The JVM-wide fake HTTP email API. */
    protected MailSink mail() {
        return MailSink.get();
    }

    /** Browser console messages, page errors and failed requests of this test, in order. */
    protected List<String> browserLog() {
        return List.copyOf(browserLog);
    }

    /** CSP violations the browser reported in this test (console text and {@code securitypolicyviolation} events). */
    protected List<String> cspViolations() {
        return List.copyOf(cspViolations);
    }

    /** Every URL the main frame navigated to in this test, in order. */
    protected List<String> navigations() {
        return List.copyOf(navigations);
    }

    /** A one-paragraph summary of the browser state, for assertion messages. */
    protected String describeBrowser() {
        return "url=" + page.url() + "\nnavigations=" + navigations + "\ncsp=" + cspViolations + "\nlog=" + browserLog;
    }

    // ------------------------------------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------------------------------------

    /** Seeds the spec's reference setup in a fresh realm (see {@link ReferenceSetup}). */
    protected ReferenceSetup.Realm referenceRealm() {
        return referenceRealm(ReferenceSetup.Options.reference());
    }

    protected ReferenceSetup.Realm referenceRealm(final ReferenceSetup.Options options) {
        return ReferenceSetup.seed(context, seed(), adminSession(), rp, mail(), options);
    }

    // ------------------------------------------------------------------------------------------------
    // Browser steps
    // ------------------------------------------------------------------------------------------------

    /** Opens the RP on its own origin and starts a sign-in (the RP 302s to the IdP's authorize endpoint). */
    protected void startSignInAtRp(final TestRelyingParty.Client client, final Map<String, String> extraAuthorizeParams) {
        page.navigate(rp.loginUrl(client, extraAuthorizeParams));
        page.waitForLoadState(LoadState.LOAD);
    }

    protected void startSignInAtRp(final TestRelyingParty.Client client) {
        startSignInAtRp(client, Map.of());
    }

    /** Fills and submits the IdP login form on the current page (like a user: typing, then clicking Sign in). */
    protected void signInWithPassword(final String username, final String password) {
        assertOnIdpPath("/login");
        page.locator("#username").fill(username);
        page.locator("#password").fill(password);
        submit(page.locator("#loginForm button[type=submit]"));
    }

    /**
     * On the two-step enrolment page: reads the secret, enters a valid code, keeps the recovery codes and follows
     * "I saved them, continue". Returns the authenticator for later sign-ins.
     */
    protected TotpDevice completeTotpEnrolment() {
        assertOnIdpPath("/mfa/enable");
        final TotpDevice device = new TotpDevice(page.locator("pre code").first().innerText().trim());
        final Locator form = page.locator("form:has(#code)");
        form.locator("#code").fill(device.nextCode());
        submit(form.locator("button[type=submit]"));
        final Locator codes = page.locator("ul.recoveryCodes code");
        if (codes.count() > 0) {
            device.recoveryCodes(codes.allInnerTexts().stream().map(String::trim).toList());
            submit(page.locator(".buttonHolder a.button"));
        }
        return device;
    }

    /** On the two-step code page: enters the next code from {@code device} and submits it. */
    protected void enterTotp(final TotpDevice device) {
        assertOnIdpPath("/mfa/totp");
        final Locator form = page.locator("form:has(#code)");
        form.locator("#code").fill(device.nextCode());
        submit(form.locator("button[type=submit]"));
    }

    /** Forgets every cookie of this test's browser (IdP session included), like closing all windows. */
    protected void clearCookies() {
        browserContext.clearCookies();
    }

    /** Clicks {@code target} and waits for whatever navigation it starts to finish loading. */
    protected void submit(final Locator target) {
        target.click();
        page.waitForLoadState(LoadState.LOAD);
    }

    /** The latest email the realm's HTTP email provider sent to {@code to} (waits up to {@link #WAIT}). */
    protected MailSink.CapturedEmail readCapturedEmail(final String to) {
        return mail().await(to, m -> true, WAIT);
    }

    /** The latest email to {@code to} whose subject or body contains {@code text}. */
    protected MailSink.CapturedEmail readCapturedEmail(final String to, final String text) {
        return mail().await(to, m -> m.subject().contains(text) || m.body().contains(text), WAIT);
    }

    /** The last hit on the RP's {@code /auth/callback}, if any. */
    protected Optional<TestRelyingParty.Callback> rpLastCallback() {
        return rp.lastCallback();
    }

    /** Every back-channel logout the RP received in this test. */
    protected List<TestRelyingParty.BackchannelLogout> rpBackchannelLogouts() {
        return rp.backchannelLogouts();
    }

    /**
     * Fails unless the browser is on the RP's {@code /auth/callback} and the RP exchanged the code and verified the
     * ID token; returns that callback.
     */
    protected TestRelyingParty.Callback assertLandedOnRpCallback() {
        final TestRelyingParty.Callback last = rp.lastCallback().orElse(null);
        if (!page.url().startsWith(rp.callbackUri() + "?") || last == null || !last.ok()) {
            throw new AssertionError("Expected to land on the RP callback " + rp.callbackUri() + " with a code the RP could"
                    + " redeem\nrp callback=" + last + "\n" + describeBrowser());
        }
        return last;
    }

    /** True when the current page is on the RP's origin. */
    protected boolean onRpOrigin() {
        return page.url().startsWith(rp.origin() + "/");
    }

    /** Fails unless the current page is {@code /realms/<realm><suffix>} on the IdP. */
    protected void assertOnIdpPath(final String suffix) {
        final URI now = URI.create(page.url());
        final boolean ok = page.url().startsWith(baseUrl() + "/realms/") && now.getPath().endsWith(suffix);
        if (!ok) {
            throw new AssertionError("Expected the IdP page …" + suffix + "\n" + describeBrowser());
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Failure capture
    // ------------------------------------------------------------------------------------------------

    private void captureFailure(final String testName, final Throwable failure) {
        if (page == null) {
            return;
        }
        final Path dir = Path.of(System.getProperty("basedir", "."), "target", "browser-failures",
                getClass().getSimpleName());
        try {
            Files.createDirectories(dir);
            page.screenshot(new Page.ScreenshotOptions().setPath(dir.resolve(testName + ".png")).setFullPage(true));
            Files.writeString(dir.resolve(testName + ".html"), page.content(), StandardCharsets.UTF_8);
            Files.writeString(dir.resolve(testName + ".txt"), "failure: " + failure + "\n\n" + describeBrowser()
                    + "\n\nrp callbacks=" + rp.callbacks() + "\nrp back-channel logouts=" + rp.backchannelLogouts()
                    + "\n", StandardCharsets.UTF_8);
            browserContext.tracing().stop(new Tracing.StopOptions().setPath(dir.resolve(testName + "-trace.zip")));
        } catch (final IOException | RuntimeException e) {
            System.err.println("Could not capture browser state for " + testName + ": " + e);
        }
    }

    /** Saves the browser state when a test fails, before {@code @AfterEach} closes the page. */
    static final class FailureCapture implements AfterTestExecutionCallback {

        @Override
        public void afterTestExecution(final ExtensionContext context) {
            final Optional<Throwable> failure = context.getExecutionException();
            if (failure.isPresent() && context.getTestInstance().orElse(null) instanceof AbstractBrowserE2eTest test) {
                test.captureFailure(context.getRequiredTestMethod().getName(), failure.get());
            }
        }
    }
}
