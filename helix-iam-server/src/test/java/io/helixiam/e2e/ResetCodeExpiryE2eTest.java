/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security: the emailed password-reset code expires ({@code helix.notification.reset-password.code-ttl}, 1 hour by
 * default) and works once. An expired, used or unknown code is refused on the reset page with the themed error, and
 * the password stays unchanged.
 */
class ResetCodeExpiryE2eTest extends AbstractE2eTest {

    private static final String NEW_PASSWORD = "Reset-Expiry-Passw0rd!";

    private JdbcTemplate jdbc() {
        return context.getBean(JdbcTemplate.class);
    }

    private void inTx(final Runnable work) {
        new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(s -> work.run());
    }

    /** Requests a reset from the public page and returns the code that was issued (read from the database). */
    private String requestReset(final E2eHttp browser, final String realmUrl, final E2eSeed.SeededUser user) {
        final E2eHttp.Response page = browser.get(realmUrl + "/reset/password?lang=en");
        final Map<String, String> form = new LinkedHashMap<>();
        form.put("_csrf", E2eHttp.csrf(page.body()));
        form.put("username", user.username());
        assertThat(browser.postForm(realmUrl + "/reset/password", form).status()).isEqualTo(200);
        final List<Map<String, Object>> rows = jdbc().queryForList(
                "SELECT code, expires_at FROM notification_code WHERE identifier = ? AND type = 'USER_RESET_PASSWORD'",
                user.userId());
        assertThat(rows).hasSize(1);
        final Instant expires = ((Timestamp) rows.get(0).get("expires_at")).toInstant();
        assertThat(expires).isBetween(Instant.now().plus(Duration.ofMinutes(59)), Instant.now().plus(Duration.ofMinutes(61)));
        return (String) rows.get(0).get("code");
    }

    private E2eHttp.Response setPassword(final E2eHttp browser, final String realmUrl, final String code) {
        final Map<String, String> form = new LinkedHashMap<>();
        form.put("_csrf", E2eHttp.csrf(browser.get(realmUrl + "/reset/password?lang=en").body()));
        form.put("code", code);
        form.put("newPassword", NEW_PASSWORD);
        form.put("repeatPassword", NEW_PASSWORD);
        return browser.postForm(realmUrl + "/reset/password/set?lang=en", form);
    }

    private String passwordHash(final String userId) {
        return jdbc().queryForObject("SELECT password FROM user_credentials WHERE user_id = ?", String.class, userId);
    }

    @Test
    void aResetCode_worksOnce_thenTheLinkSaysItWasUsed() {
        final String realm = E2eSeed.unique("acme-reset");
        seed().realm(realm, "Acme");
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("reset"), "Before-Passw0rd!");
        final String realmUrl = baseUrl() + "/realms/" + realm;
        final E2eHttp browser = newBrowser();
        final String code = requestReset(browser, realmUrl, user);

        final E2eHttp.Response open = browser.get(realmUrl + "/reset/password/" + code + "?lang=en");
        assertThat(open.body()).contains("id=\"passwordReset\"").doesNotContain("id=\"code-error\"");
        final String before = passwordHash(user.userId());
        assertThat(setPassword(browser, realmUrl, code).isRedirect()).isTrue();
        final String after = passwordHash(user.userId());
        assertThat(after).isNotEqualTo(before);

        // Used: the same link now says so, and a second submit changes nothing.
        final E2eHttp.Response reopened = browser.get(realmUrl + "/reset/password/" + code + "?lang=en");
        assertThat(reopened.body()).contains("id=\"code-error\"").contains("expired or was already used")
                .doesNotContain("id=\"passwordReset\"");
        final E2eHttp.Response again = setPassword(browser, realmUrl, code);
        assertThat(again.status()).isEqualTo(200);
        assertThat(again.body()).contains("id=\"code-error\"");
        assertThat(passwordHash(user.userId())).isEqualTo(after);
    }

    @Test
    void anExpiredResetCode_isRefused_andANewRequestIssuesAFreshCode() {
        final String realm = E2eSeed.unique("acme-reset-exp");
        seed().realm(realm, "Acme");
        final E2eSeed.SeededUser user = seed().user(realm, E2eSeed.unique("resetexp"), "Before-Passw0rd!");
        final String realmUrl = baseUrl() + "/realms/" + realm;
        final E2eHttp browser = newBrowser();
        final String code = requestReset(browser, realmUrl, user);
        inTx(() -> jdbc().update("UPDATE notification_code SET expires_at = ? WHERE code = ?",
                Timestamp.from(Instant.now().minusSeconds(1)), code));
        final String before = passwordHash(user.userId());

        assertThat(browser.get(realmUrl + "/reset/password/" + code + "?lang=en").body()).contains("id=\"code-error\"")
                .contains("id=\"request-new-link\"");
        final E2eHttp.Response submit = setPassword(browser, realmUrl, code);
        assertThat(submit.status()).isEqualTo(200);
        assertThat(submit.body()).contains("id=\"code-error\"");
        assertThat(passwordHash(user.userId())).isEqualTo(before);

        // A new request replaces the expired code; the old one stays dead.
        final String fresh = requestReset(browser, realmUrl, user);
        assertThat(fresh).isNotEqualTo(code);
        assertThat(setPassword(browser, realmUrl, fresh).isRedirect()).isTrue();
    }

    @Test
    void anUnknownCode_isRefused() {
        final E2eHttp browser = newBrowser();
        final String realmUrl = baseUrl() + "/realms/" + MASTER;
        assertThat(browser.get(realmUrl + "/reset/password/not-a-code?lang=en").body()).contains("id=\"code-error\"");
        assertThat(setPassword(browser, realmUrl, "not-a-code").body()).contains("id=\"code-error\"");
    }
}
