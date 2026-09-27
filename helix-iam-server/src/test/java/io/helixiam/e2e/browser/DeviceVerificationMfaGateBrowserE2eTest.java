/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two-step gate on the device authorization grant (RFC 8628): in a realm that requires a second factor, a browser
 * session that has not completed one cannot approve a device ({@code /oauth2/device_verification}); the device gets
 * no token until the user passed the second step and approved.
 */
class DeviceVerificationMfaGateBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Device-Gate-Passw0rd-2026!";
    private static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    @Test
    void aStalePasswordOnlySession_cannotApproveADevice_untilTheSecondFactor() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        final E2eSeed.SeededClient tv = seed().client(realm.realm(), E2eSeed.unique("tv"), List.of(DEVICE_GRANT),
                List.of(), List.of("profile"), false);
        startSignInAtRp(realm.web());
        signInWithPassword(joe.username(), joe.password());
        assertLandedOnRpCallback();
        final E2eHttp.Response mfa = adminSession().put("/admin/realms/" + realm.realm() + "/settings/mfa",
                Map.of("requireMfa", true, "skipGraceDays", 0));
        assertThat(mfa.status()).as(mfa.toString()).isEqualTo(200);

        final E2eHttp device = newBrowser();
        final String basic = "Basic " + Base64.getEncoder().encodeToString(
                (tv.clientId() + ":" + tv.secret()).getBytes(StandardCharsets.UTF_8));
        final E2eHttp.Response start = device.postForm(realm.path() + "/oauth2/device_authorization",
                Map.of("scope", "profile"), "Authorization", basic, "Accept", "application/json");
        assertThat(start.status()).as(start.toString()).isEqualTo(200);
        final String userCode = start.json().path("user_code").asText();
        final String deviceCode = start.json().path("device_code").asText();

        page().navigate(baseUrl() + realm.path() + "/activate?user_code=" + userCode);
        submit(page().locator("form button[type=submit]"));

        assertOnIdpPath("/mfa/enable");
        final E2eHttp.Response poll = device.postForm(realm.path() + "/oauth2/token",
                Map.of("grant_type", DEVICE_GRANT, "device_code", deviceCode), "Authorization", basic,
                "Accept", "application/json");
        assertThat(poll.status()).as(poll.toString()).isEqualTo(400);
        assertThat(poll.json().path("error").asText()).isEqualTo("authorization_pending");
        assertThat(poll.json().has("access_token")).isFalse();

        // After the second factor the user approves the device (the code is entered again: the approval was a POST,
        // which the saved-request resume does not replay) and the device gets its token.
        completeTotpEnrolment();
        page().navigate(baseUrl() + realm.path() + "/activate?user_code=" + userCode);
        submit(page().locator("form button[type=submit]"));
        assertOnIdpPath("/oauth2/consent"); // the device flow always confirms
        submit(page().locator("form button[type=submit]:not([form=consentCancel])"));
        final E2eHttp.Response after = device.postForm(realm.path() + "/oauth2/token",
                Map.of("grant_type", DEVICE_GRANT, "device_code", deviceCode), "Authorization", basic,
                "Accept", "application/json");
        assertThat(after.status()).as(after + "\n" + describeBrowser()).isEqualTo(200);
        assertThat(after.json().path("access_token").asText()).isNotBlank();
    }

    /** The consent page's Cancel denies the device (it used to submit the approval form with every scope checked). */
    @Test
    void cancelOnTheConsentPage_deniesTheDevice() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        final E2eSeed.SeededClient tv = seed().client(realm.realm(), E2eSeed.unique("tv"), List.of(DEVICE_GRANT),
                List.of(), List.of("profile"), false);
        final E2eHttp device = newBrowser();
        final String basic = "Basic " + Base64.getEncoder().encodeToString(
                (tv.clientId() + ":" + tv.secret()).getBytes(StandardCharsets.UTF_8));
        final E2eHttp.Response start = device.postForm(realm.path() + "/oauth2/device_authorization",
                Map.of("scope", "profile"), "Authorization", basic, "Accept", "application/json");
        assertThat(start.status()).as(start.toString()).isEqualTo(200);

        page().navigate(baseUrl() + realm.path() + "/activate?user_code=" + start.json().path("user_code").asText());
        signInWithPassword(joe.username(), joe.password());
        if (!page().url().contains("/oauth2/consent")) {
            submit(page().locator("form button[type=submit]"));
        }
        assertOnIdpPath("/oauth2/consent");
        submit(page().locator("button[form=consentCancel]"));

        final E2eHttp.Response poll = device.postForm(realm.path() + "/oauth2/token",
                Map.of("grant_type", DEVICE_GRANT, "device_code", start.json().path("device_code").asText()),
                "Authorization", basic, "Accept", "application/json");
        assertThat(poll.json().has("access_token")).as(poll + "\n" + describeBrowser()).isFalse();
        assertThat(poll.json().path("error").asText()).isIn("access_denied", "expired_token");
    }
}
