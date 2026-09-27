/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Locator;
import com.microsoft.playwright.options.LoadState;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static com.microsoft.playwright.assertions.PlaywrightAssertions.assertThat;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * B1: the realm's account console ({@code /realms/{realm}/account}) in a real browser, for a user of a realm that is
 * NOT master (every realm here is a fresh {@code monthfold-*} realm seeded like Monthfold runs it). One test per
 * action, plus the return link to the application.
 */
class AccountConsoleBrowserE2eTest extends AbstractBrowserE2eTest {

    static final String PASSWORD = "Account-Passw0rd-2026!";

    // ------------------------------------------------------------------------------------------------ overview

    @Test
    void aUserOfANonMasterRealm_signsIn_andSeesTheirOwnAccount() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        assertThat(realm.realm()).isNotEqualTo(AbstractE2eTest.MASTER);
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD,
                Map.of("given_name", "Ada", "family_name", "Lovelace"));

        page().navigate(baseUrl() + realm.path() + "/account");
        signInWithPassword(ada.username(), PASSWORD);

        assertOnIdpPath("/account");
        assertThat(page().url()).startsWith(baseUrl() + realm.path() + "/account");
        assertThat(page().locator("h1").innerText()).isEqualTo("Your account");
        assertThat(page().locator(".hx-lead").innerText()).contains("Ada Lovelace");
        assertThat(page().locator("#profile-username").innerText()).isEqualTo(ada.username());
        assertThat(page().locator("#profile-email").innerText()).contains(ada.dto().email());
        assertThat(page().locator("#email-unverified").isVisible()).isTrue();
        assertThat(page().locator("#two-step-off").isVisible()).isTrue();
        assertThat(page().locator("#session-list li").first().innerText()).contains("This browser");
        assertThat(page().locator("#delete-account").count()).as("deletion is off by default").isZero();
        assertThat(page().locator("#export").isVisible()).isTrue();
        assertThat(cspViolations()).as(describeBrowser()).isEmpty();
    }

    @Test
    void theReturnLink_isShownForTheAppsOwnOrigin_andTakesTheUserBack() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        final String back = rp().origin() + "/?from=account";

        page().navigate(accountUrl(realm, "referrer=" + ReferenceSetup.WEB + "&referrer_uri=" + enc(back)));
        signInWithPassword(ada.username(), PASSWORD);

        final Locator link = page().locator("#account-return");
        assertThat(link.innerText()).contains("Back to Monthfold web");
        assertThat(link.getAttribute("href")).isEqualTo(back);
        // It stays on every page of the visit.
        page().navigate(baseUrl() + realm.path() + "/account/password");
        assertThat(page().locator("#account-return").getAttribute("href")).isEqualTo(back);

        submit(page().locator("#account-return"));
        assertThat(page().url()).isEqualTo(back);
        assertThat(rp().landings()).containsExactly(Map.of("from", "account"));
    }

    @Test
    void aReturnAddressOffTheAppsOrigins_orOfAnUnknownApp_showsNoLink() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        page().navigate(accountUrl(realm, "referrer=" + ReferenceSetup.WEB + "&referrer_uri=" + enc("https://evil.example/")));
        signInWithPassword(ada.username(), PASSWORD);
        assertOnIdpPath("/account");
        assertThat(page().locator("#account-return").count()).isZero();

        page().navigate(accountUrl(realm, "referrer=someone-else&referrer_uri=" + enc(rp().origin() + "/")));
        assertThat(page().locator("#account-return").count()).isZero();
        page().navigate(accountUrl(realm, "referrer=" + ReferenceSetup.WEB + "&referrer_uri=" + enc("javascript:alert(1)")));
        assertThat(page().locator("#account-return").count()).isZero();
        assertThat(page().content()).doesNotContain("javascript:alert");
    }

    @Test
    void theOldProfileAddress_opensTheAccountConsole() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        page().navigate(baseUrl() + realm.path() + "/me");
        signInWithPassword(ada.username(), PASSWORD);

        assertOnIdpPath("/account");
        assertThat(page().locator("h1").innerText()).isEqualTo("Your account");
    }

    @Test
    void inARealmThatRequiresMfa_theConsoleComesAfterTheSecondStep() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser maya = seed().user(realm.realm(), E2eSeed.unique("maya"), PASSWORD);

        page().navigate(baseUrl() + realm.path() + "/account");
        signInWithPassword(maya.username(), PASSWORD);
        completeTotpEnrolment();

        assertOnIdpPath("/account");
        assertThat(page().locator("#two-step-on").isVisible()).isTrue();
        assertThat(page().locator("#authenticator-remove").count()).as("the realm requires it").isZero();
        assertThat(page().locator("#two-step").innerText()).contains("requires two-step verification");
    }

    // ------------------------------------------------------------------------------------------------ password

    @Test
    void passwordChange_needsTheCurrentPassword_andIsAudited() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        openAccount(realm, ada);

        submit(page().locator("#change-password"));
        assertOnIdpPath("/account/password");
        fillPassword("Wrong-Passw0rd-2026!", "Brand-New-Passw0rd-26!", "Brand-New-Passw0rd-26!");
        assertThat(page().locator("#password-error").innerText()).isEqualTo("Your current password is not correct.");
        fillPassword(PASSWORD, "Brand-New-Passw0rd-26!", "Another-Passw0rd-2026!");
        assertThat(page().locator("#password-error").innerText()).isEqualTo("The new passwords don't match.");
        fillPassword(PASSWORD, "short", "short");
        assertThat(page().locator("#password-error").innerText()).as("the realm's policy (12+)").isNotBlank();

        fillPassword(PASSWORD, "Brand-New-Passw0rd-26!", "Brand-New-Passw0rd-26!");
        assertOnIdpPath("/account");
        assertThat(page().locator("#account-status").innerText()).isEqualTo("Your password is changed.");

        clearCookies();
        page().navigate(accountUrl(realm, null));
        signInWithPassword(ada.username(), PASSWORD);
        assertOnIdpPath("/login");
        signInWithPassword(ada.username(), "Brand-New-Passw0rd-26!");
        assertOnIdpPath("/account");
        assertThat(awaitAudit(realm, "ACCOUNT_PASSWORD_CHANGE", "SUCCESS").path("actor").asText()).isEqualTo(ada.username());
        assertThat(awaitAudit(realm, "ACCOUNT_PASSWORD_CHANGE", "FAILURE").path("resourceId").asText()).isEqualTo(ada.userId());
    }

    // --------------------------------------------------------------------------------------- authenticator app

    @Test
    void settingUpAnAuthenticator_afterSignIn_needsNoStepUp_andShowsRecoveryCodes() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        openAccount(realm, ada);

        submit(page().locator("#authenticator-setup"));
        assertOnIdpPath("/account/authenticator");
        final TotpDevice device = enrolAuthenticatorHere();

        assertThat(device.recoveryCodes()).hasSizeGreaterThanOrEqualTo(8);
        assertOnIdpPath("/account");
        assertThat(page().locator("#two-step-on").isVisible()).isTrue();
        assertThat(page().locator("#recovery-left").innerText()).isEqualTo(device.recoveryCodes().size() + " codes left");
        awaitAudit(realm, "ACCOUNT_TOTP_ENROL", "SUCCESS");

        // The next sign-in asks for a code from the new app.
        clearCookies();
        page().navigate(accountUrl(realm, null));
        signInWithPassword(ada.username(), PASSWORD);
        enterTotp(device);
        assertOnIdpPath("/account");
    }

    @Test
    void anOldSignIn_mustConfirmItsTheUser_beforeMovingToANewApp_andTheOldAppStopsWorking() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser maya = seed().user(realm.realm(), E2eSeed.unique("maya"), PASSWORD);
        page().navigate(accountUrl(realm, null));
        signInWithPassword(maya.username(), PASSWORD);
        final TotpDevice old = completeTotpEnrolment();
        assertOnIdpPath("/account");

        ageSignIn(realm, 600);
        page().navigate(accountUrl(realm, null));
        submit(page().locator("#authenticator-setup"));
        assertOnIdpPath("/account/reauth");
        page().locator("#reauth-password").fill(PASSWORD);
        page().locator("#reauth-code").fill("000000");
        submit(page().locator("#reauth-continue"));
        assertThat(page().locator("#reauth-error").innerText()).isEqualTo("The password or the code is not correct.");
        page().locator("#reauth-password").fill(PASSWORD);
        page().locator("#reauth-code").fill(old.nextCode());
        submit(page().locator("#reauth-continue"));

        assertOnIdpPath("/account/authenticator");
        assertThat(page().locator(".hx-lead").innerText()).contains("keeps working until the new one is confirmed");
        final TotpDevice fresh = enrolAuthenticatorHere();
        assertOnIdpPath("/account");
        awaitAudit(realm, "ACCOUNT_STEP_UP", "SUCCESS");
        assertThat(awaitAudit(realm, "ACCOUNT_TOTP_ENROL", "SUCCESS").path("detail").asText()).contains("\"replaced\":\"true\"");

        clearCookies();
        page().navigate(accountUrl(realm, null));
        signInWithPassword(maya.username(), PASSWORD);
        enterTotp(old);
        assertOnIdpPath("/mfa/totp");
        assertThat(page().locator("#code-error").isVisible()).as("the old app's codes no longer work").isTrue();
        enterTotp(fresh);
        assertOnIdpPath("/account");
    }

    @Test
    void removingTheAuthenticator_needsAFreshSignIn_andTheRealmsPermission() {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);
        openAccount(realm, ada);
        submit(page().locator("#authenticator-setup"));
        final TotpDevice device = enrolAuthenticatorHere();

        ageSignIn(realm, 600);
        page().navigate(accountUrl(realm, null));
        submit(page().locator("#authenticator-remove"));
        assertOnIdpPath("/account/reauth");
        page().locator("#reauth-password").fill(PASSWORD);
        page().locator("#reauth-code").fill(device.nextCode());
        submit(page().locator("#reauth-continue"));
        assertOnIdpPath("/account/authenticator/remove");
        submit(page().locator("#remove-confirm"));

        assertOnIdpPath("/account");
        assertThat(page().locator("#account-status").innerText()).isEqualTo("Your authenticator app is removed.");
        assertThat(page().locator("#two-step-off").isVisible()).isTrue();
        awaitAudit(realm, "ACCOUNT_TOTP_REMOVE", "SUCCESS");

        // A realm that does not allow removal hides it and refuses it.
        submit(page().locator("#authenticator-setup"));
        enrolAuthenticatorHere();
        adminSession().put("/admin/realms/" + realm.realm() + "/settings/account-console",
                Map.of("allowAuthenticatorRemoval", false));
        page().navigate(accountUrl(realm, null));
        assertThat(page().locator("#authenticator-remove").count()).isZero();
        page().navigate(baseUrl() + realm.path() + "/account/authenticator/remove");
        assertOnIdpPath("/account");
        assertThat(page().locator("#account-error").innerText()).isEqualTo("That isn't available for your account.");
    }

    // ------------------------------------------------------------------------------------------ recovery codes

    @Test
    void newRecoveryCodes_needACurrentCode_andReplaceTheOldOnes() {
        final ReferenceSetup.Realm realm = referenceRealm();
        final E2eSeed.SeededUser maya = seed().user(realm.realm(), E2eSeed.unique("maya"), PASSWORD);
        page().navigate(accountUrl(realm, null));
        signInWithPassword(maya.username(), PASSWORD);
        final TotpDevice device = completeTotpEnrolment();
        final java.util.List<String> oldCodes = device.recoveryCodes();

        page().locator("#recovery-code").fill("123456");
        submit(page().locator("#recovery-form button[type=submit]"));
        assertOnIdpPath("/account");
        assertThat(page().locator("#recovery-error").innerText()).isEqualTo("That code is not valid. Try again.");

        page().locator("#recovery-code").fill(device.nextCode());
        submit(page().locator("#recovery-form button[type=submit]"));
        final java.util.List<String> newCodes = page().locator("ul.recoveryCodes code").allInnerTexts().stream()
                .map(String::trim).toList();
        assertThat(newCodes).hasSizeGreaterThanOrEqualTo(8).doesNotContainAnyElementsOf(oldCodes);
        submit(page().locator(".buttonHolder a.button"));
        assertOnIdpPath("/account");
        awaitAudit(realm, "ACCOUNT_RECOVERY_CODES_REGENERATE", "SUCCESS");
        awaitAudit(realm, "ACCOUNT_RECOVERY_CODES_REGENERATE", "FAILURE");

        // An old code no longer signs in; a new one does.
        clearCookies();
        page().navigate(accountUrl(realm, null));
        signInWithPassword(maya.username(), PASSWORD);
        useRecoveryCode(oldCodes.get(0));
        assertOnIdpPath("/mfa/recovery");
        assertThat(page().locator("#recovery-error").isVisible()).as("an old code no longer works").isTrue();
        useRecoveryCode(newCodes.get(0));
        assertOnIdpPath("/account");
    }

    // ------------------------------------------------------------------------------------------------ sessions

    @Test
    void signOutEverywhereElse_endsTheOtherBrowser_andTellsItsApp_butKeepsThisOne() throws Exception {
        final ReferenceSetup.Realm realm = referenceRealm(ReferenceSetup.Options.withoutMfa());
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);

        // Another device signs in to the app.
        final com.microsoft.playwright.Page phone = otherBrowser();
        signInToTheApp(phone, realm, joe);
        final String phoneSid = rp().lastCallback().orElseThrow().idTokenClaims().getStringClaim("sid");
        // This browser signs in to the app too, then opens the account console.
        signInToTheApp(page(), realm, joe);
        final String hereSid = rp().lastCallback().orElseThrow().idTokenClaims().getStringClaim("sid");
        assertThat(hereSid).isNotEqualTo(phoneSid);
        page().navigate(accountUrl(realm, null));
        assertThat(page().locator("#session-list li")).hasCount(2);
        assertThat(page().locator("#session-list li").nth(1).innerText()).contains("Another browser").contains("Apps: web");

        submit(page().locator("#sign-out-others"));

        assertOnIdpPath("/account");
        assertThat(page().locator("#account-status").innerText()).isEqualTo("You're signed out everywhere else.");
        assertThat(page().locator("#session-list li")).hasCount(1);
        final TestRelyingParty.BackchannelLogout logout = rp().awaitBackchannelLogout(
                l -> phoneSid.equals(l.claims().get("sid")), WAIT);
        assertThat(logout.claims()).containsEntry("sub", joe.userId());
        assertThat(rp().backchannelLogouts()).noneMatch(l -> hereSid.equals(l.claims().get("sid")));
        awaitAudit(realm, "ACCOUNT_SESSIONS_SIGN_OUT_OTHERS", "SUCCESS");

        // The other device is signed out of the IdP: the app sends it to the sign-in form again.
        phone.navigate(rp().loginUrl(realm.web()));
        phone.waitForLoadState(LoadState.LOAD);
        assertThat(URI.create(phone.url()).getPath()).isEqualTo(realm.path() + "/login");
        phone.navigate(accountUrl(realm, null));
        assertThat(URI.create(phone.url()).getPath()).isEqualTo(realm.path() + "/login");
        // This browser is still signed in, to the console and to the app.
        page().navigate(accountUrl(realm, null));
        assertOnIdpPath("/account");
        startSignInAtRp(realm.web());
        assertLandedOnRpCallback();
    }

    // ------------------------------------------------------------------------------------------------ helpers

    static String enc(final String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    String accountUrl(final ReferenceSetup.Realm realm, final String query) {
        return baseUrl() + realm.path() + "/account" + (query == null ? "" : "?" + query);
    }

    /** Signs in to the realm's account console with the password and lands on the overview. */
    void openAccount(final ReferenceSetup.Realm realm, final E2eSeed.SeededUser user) {
        page().navigate(baseUrl() + realm.path() + "/account");
        signInWithPassword(user.username(), user.password());
        page().waitForLoadState(LoadState.LOAD);
        assertOnIdpPath("/account");
    }

    void fillPassword(final String current, final String next, final String confirm) {
        page().locator("#currentPassword").fill(current);
        page().locator("#newPassword").fill(next);
        page().locator("#confirmPassword").fill(confirm);
        submit(page().locator("#password-save"));
    }

    /** On the console's authenticator page: scans the secret, confirms a code and keeps the recovery codes. */
    TotpDevice enrolAuthenticatorHere() {
        assertOnIdpPath("/account/authenticator");
        page().locator("#showCode").click();
        final TotpDevice device = new TotpDevice(page().locator("#setupKey pre code").innerText().trim());
        page().locator("#code").fill(device.nextCode());
        submit(page().locator("#authenticator-confirm"));
        device.recoveryCodes(page().locator("ul.recoveryCodes code").allInnerTexts().stream().map(String::trim).toList());
        submit(page().locator(".buttonHolder a.button"));
        return device;
    }

    /** On the two-step code page: opens "use a recovery code" and submits {@code code}. */
    void useRecoveryCode(final String code) {
        final Locator details = page().locator("details.recovery");
        if (details.getAttribute("open") == null) {
            details.locator("summary").click();
        }
        details.locator("input[name=recoveryCode]").fill(code);
        submit(details.locator("button[type=submit]"));
    }

    /** Moves this browser's sign-in {@code seconds} into the past (test-only endpoint), so the step-up applies. */
    void ageSignIn(final ReferenceSetup.Realm realm, final long seconds) {
        page().navigate(baseUrl() + realm.path() + "/e2e/age-auth-time?seconds=" + seconds);
        assertThat(page().content()).contains("auth_time=");
    }

    /** The newest audit event of {@code type} with {@code outcome} in the realm (the audit store is written async). */
    com.fasterxml.jackson.databind.JsonNode awaitAudit(final ReferenceSetup.Realm realm, final String type,
                                                      final String outcome) {
        final java.time.Instant deadline = java.time.Instant.now().plus(WAIT);
        final io.helixiam.e2e.E2eAdminSession admin = adminSession();
        do {
            final com.fasterxml.jackson.databind.JsonNode items = admin.get("/admin/realms/" + realm.realm()
                    + "/events?type=" + type + "&outcome=" + outcome).json().path("items");
            if (items.size() > 0) {
                return items.get(0);
            }
            try {
                Thread.sleep(200);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        } while (java.time.Instant.now().isBefore(deadline));
        throw new AssertionError("No audit event " + type + "/" + outcome + " in " + realm.realm());
    }

    /**
     * Signs {@code user} in to the test app in {@code tab}: the sign-in form, then (A1: the form post cannot redirect
     * to the app's origin yet) a second GET-started authorization that completes on the new IdP session.
     */
    void signInToTheApp(final com.microsoft.playwright.Page tab, final ReferenceSetup.Realm realm,
                        final E2eSeed.SeededUser user) {
        tab.navigate(rp().loginUrl(realm.web()));
        tab.waitForLoadState(LoadState.LOAD);
        tab.locator("#username").fill(user.username());
        tab.locator("#password").fill(user.password());
        tab.locator("#loginForm button[type=submit]").click();
        tab.waitForLoadState(LoadState.LOAD);
        tab.navigate(rp().loginUrl(realm.web()));
        tab.waitForLoadState(LoadState.LOAD);
        assertThat(tab.url()).startsWith(rp().callbackUri());
    }

    /** The path of the current page. */
    String path() {
        return URI.create(page().url()).getPath();
    }
}
