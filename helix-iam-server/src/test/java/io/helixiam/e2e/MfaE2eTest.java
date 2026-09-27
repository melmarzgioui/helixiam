/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 1.0 item 6: TOTP two-step sign-in in a realm with {@code requireMfa=true}. Before the fix an admin-created user
 * had no secret ({@code secret=null} in the QR code), the enrolment form posted to a realm-less path (404), the
 * realm flag was never consulted (tokens after password only), "skip" bypassed enrolment for 7 days, codes could
 * be replayed within a ±10 s window, recovery codes were unreachable, and the label carried the old product name.
 *
 * <p>The shared e2e context runs with the global {@code mfa.enabled=false}; the realm flag alone must enforce.
 */
class MfaE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Mfa-Enrolment-Passw0rd!";
    private static final Pattern SECRET = Pattern.compile("<code[^>]*>\\s*([A-Z2-7]{16,})\\s*</code>");
    private static final Pattern OTPAUTH = Pattern.compile("href=\"(otpauth://[^\"]+)\"");
    private static final Pattern RECOVERY = Pattern.compile("\\b([A-Z2-9]{4}-[A-Z2-9]{4})\\b");

    private String realm;
    private E2eSeed.SeededClient web;
    /** Signed in before requireMfa is switched on (afterwards the realm admin, too, must pass TOTP). */
    private E2eAdminSession admin;

    @BeforeEach
    void setUp() {
        realm = E2eSeed.unique("mfa");
        seed().realm(realm, "Monthfold Books");
        admin = adminSession(realm);
        final E2eHttp.Response policy = admin.put("/admin/realms/" + realm + "/settings/mfa",
                Map.of("requireMfa", true));
        assertThat(policy.status()).as(policy.toString()).isEqualTo(200);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
    }

    @Test
    void adminCreatedUser_mustEnrolWithARealSecret_beforeAnyCode_andPresentACodeOnEveryLaterSignIn() {
        final E2eSeed.SeededUser owner = seed().user(realm, E2eSeed.unique("joe"), PASSWORD);
        final AtomicReference<String> secret = new AtomicReference<>();
        final AtomicReference<List<String>> recovery = new AtomicReference<>();
        final E2eHttp browser = newBrowser();
        final OidcFlow oidc = new OidcFlow(browser, realm);

        final OidcFlow.AuthorizationResult first = oidc.authorize("web", web.redirectUri(), owner.username(), PASSWORD,
                "openid profile", page -> {
                    assertThat(page.uri().getPath()).isEqualTo("/realms/" + realm + "/mfa/enable");
                    final Matcher s = SECRET.matcher(page.body());
                    assertThat(s.find()).as("enrolment page shows a real secret: %s", page.body()).isTrue();
                    secret.set(s.group(1));
                    final Matcher uri = OTPAUTH.matcher(page.body());
                    assertThat(uri.find()).isTrue();
                    final String otpauth = URLDecoder.decode(uri.group(1).replace("&amp;", "&"), StandardCharsets.UTF_8);
                    assertThat(otpauth).startsWith("otpauth://totp/Monthfold Books:" + owner.username())
                            .contains("issuer=Monthfold Books").contains("secret=" + secret.get());
                    assertThat(page.body()).doesNotContain("value=\"skip\"");

                    // A skip attempt and a wrong code are both refused; the form posts realm-prefixed.
                    assertThat(submit(browser, page, "code", "skip").uri().getPath()).endsWith("/mfa/enable");
                    final E2eHttp.Response wrong = submit(browser, page, "code", "000000");
                    assertThat(wrong.status()).isEqualTo(200);
                    assertThat(wrong.uri().getPath()).isEqualTo("/realms/" + realm + "/mfa/enable");

                    final E2eHttp.Response codes = submit(browser, wrong, "code", totp(secret.get(), 0));
                    final E2eHttp.Response shown = browser.followRedirects(codes);
                    final List<String> found = RECOVERY.matcher(shown.body()).results().map(m -> m.group(1)).toList();
                    assertThat(found).as("recovery codes shown once: %s", shown.body()).hasSizeGreaterThanOrEqualTo(8);
                    recovery.set(found);
                    final String next = E2eHttp.formAction(shown.body(), "continue").orElse(null);
                    return next != null ? browser.postForm(next, E2eHttp.hiddenInputs(E2eHttp.form(shown.body(), "continue").orElseThrow()))
                            : browser.get(Pattern.compile("href=\"([^\"]*oauth2/authorize[^\"]*)\"").matcher(shown.body())
                                    .results().findFirst().map(m -> m.group(1).replace("&amp;", "&")).orElseThrow());
                });
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), web.redirectUri(), first.code(), first.pkce().verifier());
        assertThat(oidc.verify(tokens.accessToken()).getSubject()).isEqualTo(owner.userId());

        // Recovery codes are regenerable from the account API (session + CSRF); the old set stops working.
        final String regen = "/realms/" + realm + "/account/mfa/recovery-codes";
        browser.get("/realms/" + realm + "/account/profile", "Accept", "application/json");
        final E2eHttp.Response fresh = browser.sendJson("POST", regen, Map.of(), "X-XSRF-TOKEN",
                browser.cookieFor("XSRF-TOKEN", regen).orElseThrow(), "Accept", "application/json");
        assertThat(fresh.status()).as(fresh.toString()).isEqualTo(200);
        final List<String> oldCodes = recovery.get();
        final List<String> newCodes = new java.util.ArrayList<>();
        fresh.json().path("recoveryCodes").forEach(n -> newCodes.add(n.asText()));
        assertThat(newCodes).hasSizeGreaterThanOrEqualTo(8).doesNotContainAnyElementsOf(oldCodes);
        recovery.set(newCodes);
        final E2eHttp stale = newBrowser();
        try {
            new OidcFlow(stale, realm).authorize("web", web.redirectUri(), owner.username(), PASSWORD, "openid profile",
                    page -> submit(stale, page, "recoveryCode", oldCodes.get(1)));
            throw new AssertionError("a recovery code from the replaced set must not work");
        } catch (final AssertionError expected) {
            assertThat(expected.getMessage()).doesNotContain("from the replaced set");
        }

        // Later sign-in (new browser): password alone never yields a code; a fresh TOTP step does.
        final E2eHttp later = newBrowser();
        final String nextCode = totp(secret.get(), 30_000);
        final OidcFlow.AuthorizationResult second = new OidcFlow(later, realm).authorize("web", web.redirectUri(),
                owner.username(), PASSWORD, "openid profile", page -> {
                    assertThat(page.uri().getPath()).isEqualTo("/realms/" + realm + "/mfa/totp");
                    return submit(later, page, "code", nextCode);
                });
        assertThat(second.code()).isNotBlank();

        // Replay: the same code (same time step) is refused on another sign-in.
        final E2eHttp replay = newBrowser();
        final AtomicReference<String> landed = new AtomicReference<>();
        try {
            new OidcFlow(replay, realm).authorize("web", web.redirectUri(), owner.username(), PASSWORD, "openid profile",
                    page -> {
                        landed.set(page.uri().getPath());
                        return submit(replay, page, "code", nextCode);
                    });
            throw new AssertionError("a replayed TOTP code must not complete the sign-in");
        } catch (final AssertionError expected) {
            assertThat(expected.getMessage()).doesNotContain("a replayed TOTP code");
        }
        assertThat(landed.get()).endsWith("/mfa/totp");

        // Recovery code: works once (no broker involved), refused the second time.
        final String code = recovery.get().get(0);
        final E2eHttp rec = newBrowser();
        final OidcFlow.AuthorizationResult viaRecovery = new OidcFlow(rec, realm).authorize("web", web.redirectUri(),
                owner.username(), PASSWORD, "openid profile", page -> submit(rec, page, "recoveryCode", code));
        assertThat(viaRecovery.code()).isNotBlank();
        final E2eHttp again = newBrowser();
        try {
            new OidcFlow(again, realm).authorize("web", web.redirectUri(), owner.username(), PASSWORD, "openid profile",
                    page -> submit(again, page, "recoveryCode", code));
            throw new AssertionError("a used recovery code must not complete the sign-in");
        } catch (final AssertionError expected) {
            assertThat(expected.getMessage()).doesNotContain("a used recovery code");
        }
    }

    @Test
    void skip_isOffByDefault_andAllowedOnlyWithinTheRealmsGracePeriod() {
        final E2eHttp.Response grace = admin.put("/admin/realms/" + realm + "/settings/mfa",
                Map.of("skipGraceDays", 7));
        assertThat(grace.status()).as(grace.toString()).isEqualTo(200);
        assertThat(grace.json().path("skipGraceDays").asInt()).isEqualTo(7);

        final E2eSeed.SeededUser fresh = seed().user(realm, E2eSeed.unique("maya"), PASSWORD);
        final E2eHttp browser = newBrowser();
        final OidcFlow.AuthorizationResult r = new OidcFlow(browser, realm).authorize("web", web.redirectUri(),
                fresh.username(), PASSWORD, "openid profile", page -> {
                    assertThat(page.body()).contains("value=\"skip\"");
                    return submit(browser, page, "code", "skip");
                });
        assertThat(r.code()).isNotBlank();

        assertThat(admin.put("/admin/realms/" + realm + "/settings/mfa", Map.of("skipGraceDays", -1))
                .status()).isEqualTo(400);

        // A new admin sign-in in this realm is itself held behind the second factor: no admin API access.
        final E2eHttp.Response gated = adminSession(realm).get("/admin/realms/" + realm + "/clients");
        assertThat(gated.status()).as(gated.toString()).isIn(401, 403);
    }

    @Test
    void wrongSecondFactorCodes_areCappedPerSignIn_thenThePasswordIsNeededAgain() {
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("brute"), PASSWORD);
        final String secret = enrol(user);

        final E2eHttp http = newBrowser();
        final AtomicReference<E2eHttp.Response> totpPage = new AtomicReference<>();
        try {
            new OidcFlow(http, realm).authorize("web", web.redirectUri(), user.username(), PASSWORD, "openid",
                    page -> { totpPage.set(page); throw new StopAtPage(); });
        } catch (final StopAtPage expected) {
            // the second-factor page is reached; we drive it by hand below
        }
        E2eHttp.Response page = totpPage.get();
        assertThat(page.uri().getPath()).endsWith("/mfa/totp");
        for (int attempt = 1; attempt <= 4; attempt++) {
            page = submit(http, page, "code", "000000");
            assertThat(page.status()).as("attempt %d stays on the TOTP page", attempt).isEqualTo(200);
        }
        // A wrong recovery code counts too; the 5th failure ends this sign-in.
        final E2eHttp.Response fifth = submit(http, page, "recoveryCode", "AAAA-AAAA");
        assertThat(fifth.isRedirect()).as(fifth.toString()).isTrue();
        assertThat(fifth.location().toString()).contains("/realms/" + realm + "/login").contains("error=mfaLocked");

        // Even the right code no longer works in that session: the password is needed again.
        final Map<String, String> fields = new LinkedHashMap<>(E2eHttp.hiddenInputs(E2eHttp.form(page.body(), "name=\"code\"").orElseThrow()));
        fields.put("code", totp(secret, 30_000));
        final E2eHttp.Response late = http.postForm("/realms/" + realm + "/mfa/totp", fields);
        assertThat(late.isRedirect() && late.location().toString().contains("/oauth2/authorize")).as(late.toString()).isFalse();
    }

    /** Enrols TOTP for {@code user} through a real sign-in; returns the secret. */
    private String enrol(final E2eSeed.SeededUser user) {
        final E2eHttp http = newBrowser();
        final AtomicReference<String> secret = new AtomicReference<>();
        new OidcFlow(http, realm).authorize("web", web.redirectUri(), user.username(), PASSWORD, "openid", page -> {
            final Matcher s = SECRET.matcher(page.body());
            assertThat(s.find()).isTrue();
            secret.set(s.group(1));
            final E2eHttp.Response codes = http.followRedirects(submit(http, page, "code", totp(secret.get(), 0)));
            return http.get(Pattern.compile("href=\"([^\"]*oauth2/authorize[^\"]*)\"").matcher(codes.body())
                    .results().findFirst().map(m -> m.group(1).replace("&amp;", "&")).orElseThrow());
        });
        return secret.get();
    }

    private static final class StopAtPage extends RuntimeException {
    }

    /** Submits the page's form containing {@code field} with that value (plus its hidden inputs). */
    private static E2eHttp.Response submit(final E2eHttp http, final E2eHttp.Response page, final String field, final String value) {
        final String marker = "value=\"skip\"".equals(value) ? "value=\"skip\"" : "name=\"" + field + "\"";
        final String html = "skip".equals(value)
                ? E2eHttp.form(page.body(), "value=\"skip\"").orElse(E2eHttp.form(page.body(), marker).orElseThrow())
                : E2eHttp.form(page.body(), marker).orElseThrow(() -> new AssertionError("no form with " + marker + ": " + page));
        final String action = "skip".equals(value)
                ? E2eHttp.formAction(page.body(), "value=\"skip\"").orElse(E2eHttp.formAction(page.body(), marker).orElseThrow())
                : E2eHttp.formAction(page.body(), marker).orElseThrow();
        assertThat(action).as("MFA forms post realm-prefixed paths").startsWith("/realms/");
        final Map<String, String> fields = new LinkedHashMap<>(E2eHttp.hiddenInputs(html));
        fields.put(field, value);
        return http.postForm(action, fields);
    }

    private static String totp(final String secret, final long offsetMillis) {
        try {
            return TimeBasedOneTimePasswordUtil.generateNumberString(secret, System.currentTimeMillis() + offsetMillis,
                    TimeBasedOneTimePasswordUtil.DEFAULT_TIME_STEP_SECONDS, TimeBasedOneTimePasswordUtil.DEFAULT_OTP_LENGTH);
        } catch (final java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
