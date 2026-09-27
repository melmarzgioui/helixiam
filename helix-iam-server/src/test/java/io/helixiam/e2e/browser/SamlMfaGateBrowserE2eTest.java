/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import com.microsoft.playwright.Route;
import io.helixiam.e2e.E2eHttp;
import io.helixiam.e2e.E2eSeed;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two-step gate on the SAML IdP: in a realm that requires a second factor, no SAML assertion is issued to a
 * browser session that has not completed one — SP-initiated (Redirect and POST binding), IdP-initiated, with
 * {@code ForceAuthn} and with {@code IsPassive} (answered with a {@code NoPassive} status at the SP's ACS). The SP's
 * ACS is on another site ({@code https://sp.monthfold.test}); the browser's POSTs to it are intercepted and recorded.
 */
class SamlMfaGateBrowserE2eTest extends AbstractBrowserE2eTest {

    private static final String PASSWORD = "Saml-Gate-Passw0rd-2026!";
    private static final String SP_ORIGIN = "https://sp.monthfold.test";
    private static final String ACS = SP_ORIGIN + "/saml/acs";

    /** Every SAMLResponse the browser delivered to the SP's ACS (decoded XML), in order. */
    private final List<String> delivered = new CopyOnWriteArrayList<>();
    private String spEntityId;

    @BeforeEach
    void interceptTheSpsAcs() {
        delivered.clear();
        page().route(SP_ORIGIN + "/**", (final Route route) -> {
            final String body = route.request().postData();
            if (body != null) {
                for (final String pair : body.split("&")) {
                    final int eq = pair.indexOf('=');
                    if (eq > 0 && "SAMLResponse".equals(pair.substring(0, eq))) {
                        delivered.add(new String(Base64.getMimeDecoder().decode(
                                URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8)), StandardCharsets.UTF_8));
                    }
                }
            }
            route.fulfill(new Route.FulfillOptions().setStatus(200).setContentType("text/html")
                    .setBody("<!doctype html><title>SP</title><p id=sp-acs>received</p>"));
        });
    }

    // ------------------------------------------------------------------------------------------------ gaps

    @Test
    void aFederatedSession_getsNoAssertion_untilTheSecondFactor() {
        final ReferenceSetup.Realm realm = samlRealm(true);
        final E2eSeed.SeededUser ada = seed().user(realm.realm(), E2eSeed.unique("ada"), PASSWORD);

        // The SP starts SSO; the user signs in at the upstream identity provider (the stub stands in for its callback).
        page().navigate(redirectBindingUrl(realm, authnRequest(false, false)));
        assertOnIdpPath("/login");
        page().navigate(baseUrl() + realm.path() + "/broker/e2e-stub/complete?userId=" + ada.userId());

        assertNoAssertion("a federated session");
        assertOnIdpPath("/mfa/enable");
        completeTotpEnrolment();
        assertThat(lastDelivered()).as("after the second factor the SSO request resumes").contains("Assertion")
                .contains(":Success\"");
    }

    @Test
    void aStalePasswordOnlySession_getsNoAssertion_redirectBinding() {
        final ReferenceSetup.Realm realm = staleSession();
        page().navigate(redirectBindingUrl(realm, authnRequest(false, false)));
        assertNoAssertion("Redirect binding on a stale password-only session");
        assertOnIdpPath("/mfa/enable");
        completeTotpEnrolment();
        assertThat(lastDelivered()).as("resumed after enrolment").contains("Assertion");
    }

    @Test
    void aStalePasswordOnlySession_getsNoAssertion_postBinding() {
        final ReferenceSetup.Realm realm = staleSession();
        postBinding(realm, authnRequest(false, false));
        assertNoAssertion("POST binding on a stale password-only session");
        // The SP's cross-site POST carries no session cookie (SameSite=Lax), so the IdP asks for a sign-in; either way
        // there is no assertion. The controller-level gate for POST binding is covered in SamlIdpControllerTest.
        assertThat(page().url()).as(describeBrowser()).containsAnyOf("/login", "/mfa/enable");
    }

    @Test
    void aStalePasswordOnlySession_getsNoAssertion_idpInitiated() {
        final ReferenceSetup.Realm realm = staleSession();
        page().navigate(baseUrl() + realm.path() + "/saml/idp/sso?sp=" + enc(spEntityId));
        assertNoAssertion("IdP-initiated SSO on a stale password-only session");
        assertOnIdpPath("/mfa/enable");
        completeTotpEnrolment();
        assertThat(lastDelivered()).as("IdP-initiated SSO resumed after enrolment").contains("Assertion");
    }

    /** A realm without the requirement, a password-only SAML sign-in, then the realm requires a second factor. */
    private ReferenceSetup.Realm staleSession() {
        final ReferenceSetup.Realm realm = samlRealm(false);
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        signInThroughSaml(realm, joe);
        requireMfa(realm);
        return realm;
    }

    @Test
    void isPassive_withoutTheSecondFactor_isAnsweredWithNoPassive_atTheSpsAcs() {
        final ReferenceSetup.Realm realm = samlRealm(false);
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        signInThroughSaml(realm, joe);
        requireMfa(realm);

        page().navigate(redirectBindingUrl(realm, authnRequest(false, true)));

        assertThat(lastDelivered()).contains("urn:oasis:names:tc:SAML:2.0:status:NoPassive").doesNotContain("Assertion");
    }

    // ------------------------------------------------------------------------------------------------ blocked

    @Test
    void midEnrolment_getsNoAssertion_evenWithForceAuthnOrIsPassive() {
        final ReferenceSetup.Realm realm = samlRealm(true);
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        page().navigate(redirectBindingUrl(realm, authnRequest(false, false)));
        signInWithPassword(joe.username(), joe.password());
        assertOnIdpPath("/mfa/enable");

        page().navigate(redirectBindingUrl(realm, authnRequest(false, false)));
        assertNoAssertion("mid-enrolment");
        page().navigate(baseUrl() + realm.path() + "/saml/idp/sso?sp=" + enc(spEntityId));
        assertNoAssertion("IdP-initiated mid-enrolment");
        page().navigate(redirectBindingUrl(realm, authnRequest(true, false)));
        assertNoAssertion("ForceAuthn mid-enrolment");
        page().navigate(redirectBindingUrl(realm, authnRequest(false, true)));
        assertThat(delivered.stream().filter(r -> r.contains("Assertion")).toList()).as("IsPassive mid-enrolment").isEmpty();
    }

    @Test
    void forceAuthn_reAuthenticatesWithBothFactors_beforeTheAssertion() {
        final ReferenceSetup.Realm realm = samlRealm(true);
        final E2eSeed.SeededUser joe = seed().user(realm.realm(), E2eSeed.unique("joe"), PASSWORD);
        page().navigate(redirectBindingUrl(realm, authnRequest(false, false)));
        signInWithPassword(joe.username(), joe.password());
        final TotpDevice device = completeTotpEnrolment();
        assertThat(lastDelivered()).contains("Assertion");
        delivered.clear();

        page().navigate(redirectBindingUrl(realm, authnRequest(true, false)));
        assertOnIdpPath("/login");
        signInWithPassword(joe.username(), joe.password());
        assertNoAssertion("ForceAuthn after the password only");
        enterTotp(device);
        assertThat(lastDelivered()).contains("Assertion");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** The reference realm (MFA on or off) with a SAML service provider whose ACS is on another site. */
    private ReferenceSetup.Realm samlRealm(final boolean requireMfa) {
        final ReferenceSetup.Realm realm = referenceRealm(requireMfa ? ReferenceSetup.Options.reference()
                : ReferenceSetup.Options.withoutMfa());
        spEntityId = "https://sp.monthfold.test/" + E2eSeed.unique("sp");
        final Map<String, Object> options = new LinkedHashMap<>();
        options.put("idpInitiatedSsoEnabled", true);
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("entityId", spEntityId);
        body.put("assertionConsumerServiceUrl", ACS);
        body.put("enabled", true);
        body.put("options", options);
        final E2eHttp.Response created = adminSession().post("/admin/realms/" + realm.realm() + "/saml-clients", body);
        assertThat(created.status()).as(created.toString()).isEqualTo(201);
        return realm;
    }

    /** A password-only SAML sign-in in a realm without the requirement: the SP gets its assertion. */
    private void signInThroughSaml(final ReferenceSetup.Realm realm, final E2eSeed.SeededUser user) {
        page().navigate(redirectBindingUrl(realm, authnRequest(false, false)));
        signInWithPassword(user.username(), user.password());
        assertThat(lastDelivered()).as("baseline: the SAML SSO works").contains("Assertion");
        delivered.clear();
    }

    private void requireMfa(final ReferenceSetup.Realm realm) {
        final E2eHttp.Response r = adminSession().put("/admin/realms/" + realm.realm() + "/settings/mfa",
                Map.of("requireMfa", true, "skipGraceDays", 0));
        assertThat(r.status()).as(r.toString()).isEqualTo(200);
    }

    private String authnRequest(final boolean forceAuthn, final boolean isPassive) {
        return "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\""
                + " xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_" + UUID.randomUUID() + "\""
                + " Version=\"2.0\" IssueInstant=\"" + Instant.now() + "\" AssertionConsumerServiceURL=\"" + ACS + "\""
                + (forceAuthn ? " ForceAuthn=\"true\"" : "") + (isPassive ? " IsPassive=\"true\"" : "")
                + "><saml:Issuer>" + spEntityId + "</saml:Issuer></samlp:AuthnRequest>";
    }

    private String redirectBindingUrl(final ReferenceSetup.Realm realm, final String xml) {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflate = new DeflaterOutputStream(out, new Deflater(Deflater.DEFLATED, true))) {
            deflate.write(xml.getBytes(StandardCharsets.UTF_8));
        } catch (final java.io.IOException e) {
            throw new IllegalStateException(e);
        }
        return baseUrl() + realm.path() + "/saml/idp/sso?SAMLRequest="
                + enc(Base64.getEncoder().encodeToString(out.toByteArray())) + "&RelayState=rs-1";
    }

    /** POST binding: an auto-submitted form from the SP's site, like a real SP page. */
    private void postBinding(final ReferenceSetup.Realm realm, final String xml) {
        final String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        page().navigate(SP_ORIGIN + "/start");
        page().setContent("<form id=f method=post action=\"" + baseUrl() + realm.path() + "/saml/idp/sso\">"
                + "<input type=hidden name=SAMLRequest value=\"" + encoded + "\"><input type=hidden name=RelayState value=rs-2>"
                + "<button type=submit>go</button></form>");
        submit(page().locator("#f button"));
    }

    private void assertNoAssertion(final String what) {
        final List<String> assertions = new ArrayList<>(delivered.stream().filter(r -> r.contains("Assertion")).toList());
        assertThat(assertions).as(what + ": the SP must not receive an assertion\n" + describeBrowser()).isEmpty();
        assertThat(page().content()).as(what + ": no assertion on the page").doesNotContain("name=\"SAMLResponse\"");
    }

    private String lastDelivered() {
        final long deadline = System.currentTimeMillis() + WAIT.toMillis();
        while (delivered.isEmpty() && System.currentTimeMillis() < deadline) {
            page().waitForTimeout(100);
        }
        assertThat(delivered).as(describeBrowser()).isNotEmpty();
        return delivered.get(delivered.size() - 1);
    }

    private static String enc(final String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
