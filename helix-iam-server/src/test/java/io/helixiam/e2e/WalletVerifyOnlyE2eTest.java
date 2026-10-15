/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.nimbusds.jwt.JWTClaimsSet;
import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowCreateDto;
import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import io.helixiam.authorization.amqp.flow.FlowSaveDto;
import io.helixiam.authorization.domain.audit.AuditQuery;
import io.helixiam.authorization.domain.audit.AuditRecord;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.federation.wallet.WalletSubjectResolver;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.service.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verify-only / step-up EUDI wallet mode ({@code subject.strategy=NONE}), end to end over real HTTP with the in-repo
 * test wallet. The {@code bank} client runs a flow whose wallet verification step follows the first factor (here a
 * federated sign-in at eIDAS substantial, through the e2e broker stub: the shared e2e context keeps the flow engine off
 * for password logins, which a federated login never bypasses): the user's own linked wallet steps the login up to
 * eIDAS high and releases ONLY the configured claims ({@code age_over_18}, {@code nationalities}) as
 * {@code verified_claims}; another person's wallet is refused; no account is ever created or linked; and an SSO
 * session without the wallet is stepped up through {@code acr_values}.
 */
class WalletVerifyOnlyE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Wallet-Verify-Passw0rd-2026!";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    private static final String STEP_UP_FLOW = "wallet-stepup";

    private WalletE2eFixture wallet;
    private String realm;
    private E2eSeed.SeededClient web;
    private E2eSeed.SeededClient bank;
    private E2eSeed.SeededClient bankConsent;
    private String loginAlias;
    private String verifyAlias;
    private WalletLinkService links;
    private E2eSeed.SeededUser ada;
    private String adaNumber;
    private String bobNumber;
    private WalletIdentityProvider login;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("wverify");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "verified_claims"));
        loginAlias = E2eSeed.unique("eudi-login");
        verifyAlias = E2eSeed.unique("eudi-verify");
        login = wallet.storedProvider(realm, loginAlias, Map.of());
        final WalletIdentityProvider verify = wallet.storedProvider(realm, verifyAlias, Map.of(
                "subject.strategy", "NONE",
                "verify.linkedProvider", loginAlias,
                "pid.requestedClaims", "[\"birthdate\",\"nationalities\"]",
                "verify.releasedClaims", "[\"age_over_18\",\"nationalities\"]"));
        wallet.install(realm, login, verify);

        // ada and bob each linked their own wallet (administrative number) at the login connection
        links = context.getBean(WalletLinkService.class);
        ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eSeed.SeededUser bob = seed().user(realm, E2eSeed.unique("bob"), PASSWORD);
        adaNumber = "PAN-" + UUID.randomUUID();
        bobNumber = "PAN-" + UUID.randomUUID();
        assertThat(links.link(realm, ada.userId(), loginAlias, numberSubject(adaNumber)))
                .isEqualTo(WalletLinkService.LinkResult.LINKED);
        assertThat(links.link(realm, bob.userId(), loginAlias, numberSubject(bobNumber)))
                .isEqualTo(WalletLinkService.LinkResult.LINKED);

        // the bank's own login flow: the wallet verification after the password
        final FlowAdminPublisher flows = context.getBean(FlowAdminPublisher.class);
        flows.create(new FlowCreateDto(realm, STEP_UP_FLOW, null));
        flows.save(new FlowSaveDto(realm, STEP_UP_FLOW, List.of(new FlowExecutionDto("wallet-verify", null,
                "eudi-wallet-verify", "REQUIRED", false, 10, Map.of("providerAlias", verifyAlias)))));
        // the bank client is bound to that flow (its Applications → Login flow); "bankc" too, with a consent page
        bank = boundClient("bank", false);
        bankConsent = boundClient("bankc", true);
        assertThat(context.getBean(io.helixiam.authorization.amqp.AuthFlowPublisher.class).retrieveFlowForClient(
                io.helixiam.authorization.support.RealmScopedKey.pack(realm, "bank")).getAlias())
                .as("the bank runs the step-up flow").isEqualTo(STEP_UP_FLOW);
    }

    @Test
    void theUsersOwnWallet_stepsUpToHigh_releasesOnlyTheConfiguredClaims_andCreatesOrLinksNothing() {
        final Snapshot before = snapshot();
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();

        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bank", Map.of());
        final String tx = WalletE2eFixture.txId(walletPage.uri().getPath() + "?" + walletPage.uri().getRawQuery());
        assertThat(walletPage.body()).as("the wallet page says verify, not sign in")
                .contains("Confirm with your EUDI Wallet");
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));

        final OidcFlow.Tokens tokens = tokens(browser, pkce, "bank", bank, signedIn);
        final OidcFlow oidc = new OidcFlow(browser, realm);
        final JWTClaimsSet id = oidc.verify(tokens.idToken());
        assertThat(id.getSubject()).isEqualTo(ada.userId());
        assertThat(id.getClaim("acr")).isEqualTo(HIGH);
        assertThat(id.getClaim("verified_claims")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        final Map<String, Object> verified = (Map<String, Object>) id.getClaim("verified_claims");
        assertThat(verified.get("claims")).as("only the released claims, never the birth date or names")
                .isEqualTo(Map.of("age_over_18", true, "nationalities", "DE,NL"));
        @SuppressWarnings("unchecked")
        final Map<String, Object> verification = (Map<String, Object>) verified.get("verification");
        assertThat(verification).containsEntry("trust_framework", "eidas").containsEntry("assurance_level", HIGH);
        assertThat(id.getClaims()).doesNotContainKeys("given_name", "family_name", "birthdate", "nationalities");
        assertThat(id.toString()).doesNotContain("Erika").doesNotContain("1984").doesNotContain(adaNumber);

        // the claims went to the code exchange's ID token only: not kept on the stored authorization, not on refresh
        final org.springframework.security.oauth2.server.authorization.OAuth2Authorization stored = context.getBean(
                org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService.class)
                .findByToken(tokens.accessToken(),
                        org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN);
        assertThat(stored).isNotNull();
        assertThat(stored.getAttributes()).doesNotContainKey("helix_verified_claims");
        assertThat(String.valueOf(stored.getAttributes())).doesNotContain("DE,NL").doesNotContain("age_over_18");
        assertThat(tokens.refreshToken()).isNotBlank();
        final OidcFlow.Tokens refreshed = oidc.refresh("bank", bank.secret(), tokens.refreshToken());
        if (refreshed.idToken() != null) {
            final JWTClaimsSet again = oidc.verify(refreshed.idToken());
            assertThat(again.getClaim("verified_claims")).as("never on a refresh").isNull();
            assertThat(again.getClaim("acr")).isEqualTo(HIGH);
        }

        assertThat(snapshot()).as("no account created, no link added").isEqualTo(before);
        assertThat(links.find(realm, verifyAlias, numberSubject(adaNumber))).isEmpty();
        final List<AuditRecord> success = awaitAudits("WALLET_VERIFY_SUCCESS", tx, 1);
        assertThat(success).hasSize(1);
        assertThat(success.get(0).actor()).isEqualTo(ada.userId());
        assertThat(success.get(0).detail()).contains("\"releasedClaims\":\"age_over_18,nationalities\"")
                .doesNotContain("DE,NL");
        assertThat(audits("WALLET_LOGIN_SUCCESS", tx)).as("a verification is never a login").isEmpty();
    }

    @Test
    void anotherPersonsWallet_isRefused_andTheUsersOwnWalletThenSucceeds() {
        final Snapshot before = snapshot();
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();

        // ada signed in with her password, then presents bob's wallet
        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bank", Map.of());
        final String tx = WalletE2eFixture.txId(walletPage.uri().getPath() + "?" + walletPage.uri().getRawQuery());
        final E2eHttp.Response refused = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(bobNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(refused.locationStartsWith(E2eSeed.REDIRECT_URI)).as("no code for a swapped wallet").isFalse();
        assertThat(refused.body()).as(refused + "\n" + browser.trail(8)).contains("id=\"walletVerifyError\"");
        final List<AuditRecord> failure = awaitAudits("WALLET_VERIFY_FAILURE", tx, 1);
        assertThat(failure).hasSize(1);
        assertThat(failure.get(0).actor()).isEqualTo(ada.userId());
        assertThat(failure.get(0).detail()).contains("\"reason\":\"BINDING_MISMATCH\"");

        // a wallet nobody linked is refused too, and creates nothing
        final E2eHttp.Response second = browser.followRedirects(browser.postForm(E2eHttp.formAction(refused.body(),
                "name=\"restart\"").orElseThrow(), Map.of("_csrf", E2eHttp.csrf(refused.body()), "restart", "1")));
        assertThat(second.uri().getPath()).as(second + "\n" + browser.trail(8))
                .isEqualTo("/realms/" + realm + "/broker/" + verifyAlias + "/wallet");
        final E2eHttp.Response strangerRefused = browser.followRedirectsUntil(browser.get(present(browser, second,
                pid("PAN-" + UUID.randomUUID()))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(strangerRefused.body()).contains("id=\"walletVerifyError\"");

        // "try again" with her own wallet completes the login
        final E2eHttp.Response third = browser.followRedirects(browser.postForm(E2eHttp.formAction(
                strangerRefused.body(), "name=\"restart\"").orElseThrow(), Map.of("_csrf",
                E2eHttp.csrf(strangerRefused.body()), "restart", "1")));
        assertThat(third.uri().getPath()).isEqualTo("/realms/" + realm + "/broker/" + verifyAlias + "/wallet");
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(present(browser, third,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        final JWTClaimsSet id = idToken(browser, pkce, "bank", bank, signedIn);
        assertThat(id.getSubject()).isEqualTo(ada.userId());
        assertThat(id.getClaim("acr")).isEqualTo(HIGH);
        assertThat(snapshot()).as("refusals create and link nothing").isEqualTo(before);
    }

    @Test
    void anSsoSessionWithoutTheWallet_isSteppedUpThroughAcrValues() {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce webPkce = OidcFlow.Pkce.create();
        // signed in to "web" through the federated first factor without a level of assurance: no acr
        final String webAuthorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid&state=st&code_challenge="
                + webPkce.challenge() + "&code_challenge_method=S256";
        browser.followRedirects(browser.get(webAuthorize, "Accept", "text/html"));
        final E2eHttp.Response webSignedIn = browser.followRedirectsUntil(browser.get("/realms/" + realm
                + "/broker/e2e-stub/complete?userId=" + ada.userId()), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        final JWTClaimsSet webId = idToken(browser, webPkce, "web", web, webSignedIn);
        assertThat(webId.getClaim("acr")).isNull();
        assertThat(webId.getClaim("verified_claims")).isNull();

        // the bank asks for eIDAS high: the session does not satisfy it, so the user signs in again and steps up
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bank", Map.of("acr_values", HIGH));
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        final JWTClaimsSet id = idToken(browser, pkce, "bank", bank, signedIn);
        assertThat(id.getSubject()).isEqualTo(ada.userId());
        assertThat(id.getClaim("acr")).isEqualTo(HIGH);

        // a later code for "web" in the same session (SSO) gets the acr, but not the bank's verified claims
        final OidcFlow.Pkce laterPkce = OidcFlow.Pkce.create();
        final E2eHttp.Response later = browser.followRedirectsUntil(browser.get("/realms/" + realm
                + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri=" + E2eSeed.REDIRECT_URI
                + "&scope=openid&state=st&code_challenge=" + laterPkce.challenge() + "&code_challenge_method=S256",
                "Accept", "text/html"), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        final JWTClaimsSet webAgain = idToken(browser, laterPkce, "web", web, later);
        assertThat(webAgain.getClaim("acr")).isEqualTo(HIGH);
        assertThat(webAgain.getClaim("verified_claims")).as("released to the bank's code only").isNull();
    }

    @Test
    void withoutTheVerifiedClaimsScope_theLoginIsSteppedUp_butNothingIsReleased() {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bank", Map.of("scope", "openid"));
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        final JWTClaimsSet id = idToken(browser, pkce, "bank", bank, signedIn);
        assertThat(id.getClaim("acr")).isEqualTo(HIGH);
        assertThat(id.getClaim("verified_claims")).isNull();
    }

    @Test
    void anAuthorizeRequestOfAnotherClientInASecondTab_neverReceivesTheClaims() {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bank", Map.of());
        // a second tab: "web" asks for verified_claims too; its request replaces the saved one
        final OidcFlow.Pkce webPkce = OidcFlow.Pkce.create();
        browser.followRedirects(browser.get("/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=" + encode("openid verified_claims")
                + "&state=tab2&code_challenge=" + webPkce.challenge() + "&code_challenge_method=S256",
                "Accept", "text/html"));
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + browser.trail(10)).isTrue();
        final String code = OidcFlow.query(signedIn.location()).get("code");
        final String state = OidcFlow.query(signedIn.location()).get("state");
        final OidcFlow oidc = new OidcFlow(browser, realm);
        if ("tab2".equals(state)) {
            // the second tab's request was resumed: it is not the request the step was pinned to
            assertThat(oidc.verify(oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI, code,
                    webPkce.verifier()).idToken()).getClaim("verified_claims")).isNull();
            return;
        }
        // the bank's request was resumed: it gets the claims, and web's pending request (resumed now, over SSO) none
        assertThat(oidc.verify(oidc.exchangeCode("bank", bank.secret(), E2eSeed.REDIRECT_URI, code,
                pkce.verifier()).idToken()).getClaim("verified_claims")).isNotNull();
        final E2eHttp.Response webSignedIn = browser.followRedirectsUntil(browser.get("/realms/" + realm
                + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri=" + E2eSeed.REDIRECT_URI
                + "&scope=" + encode("openid verified_claims") + "&state=tab2&code_challenge=" + webPkce.challenge()
                + "&code_challenge_method=S256"), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(idToken(browser, webPkce, "web", web, webSignedIn).getClaim("verified_claims"))
                .as("released for the bank's request, never web's").isNull();
    }

    @Test
    void consentDenied_dropsTheClaims_andALaterPromptNoneOfAnotherClientGetsNone() {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bankc", Map.of());
        final E2eHttp.Response consent = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(consent.status()).as(consent + "\n" + browser.trail(8)).isEqualTo(200);
        final String formHtml = E2eHttp.form(consent.body(), "name=\"state\"").orElseThrow();
        // deny: the consent form's hidden fields only, no scope approved
        final E2eHttp.Response denied = browser.followRedirectsUntil(browser.postForm(
                E2eHttp.formAction(consent.body(), "name=\"state\"").orElseThrow(), E2eHttp.hiddenInputs(formHtml)),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(denied.location().toString()).contains("error=access_denied");

        final OidcFlow.Pkce webPkce = OidcFlow.Pkce.create();
        final E2eHttp.Response silent = browser.followRedirectsUntil(browser.get("/realms/" + realm
                + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri=" + E2eSeed.REDIRECT_URI
                + "&scope=" + encode("openid verified_claims") + "&prompt=none&state=silent&code_challenge="
                + webPkce.challenge() + "&code_challenge_method=S256"), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        final JWTClaimsSet id = idToken(browser, webPkce, "web", web, silent);
        assertThat(id.getClaim("verified_claims")).isNull();
    }

    @Test
    void startingTheVerifyConnectionAtTheBroker_midStep_doesNotBreakTheStep() {
        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final E2eHttp.Response walletPage = signInThenWalletPage(browser, pkce, "bank", Map.of());
        assertThat(browser.get("/realms/" + realm + "/broker/" + verifyAlias).status()).isEqualTo(302);
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.get(present(browser, walletPage,
                pid(adaNumber))), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(idToken(browser, pkce, "bank", bank, signedIn).getClaim("acr")).isEqualTo(HIGH);
    }

    @Test
    void theVerifyOnlyConnection_isNeverASignInMethod() {
        final E2eHttp browser = newBrowser();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid&state=st&code_challenge="
                + OidcFlow.Pkce.create().challenge() + "&code_challenge_method=S256";
        final String loginPage = browser.followRedirects(browser.get(authorize, "Accept", "text/html")).body();
        assertThat(loginPage).contains("/broker/" + loginAlias).doesNotContain("/broker/" + verifyAlias);
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + verifyAlias);
        assertThat(start.status()).isEqualTo(302);
        assertThat(start.location().toString()).contains("/login").contains("error");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** A confidential client bound to the step-up flow, asking for openid and verified_claims. */
    private E2eSeed.SeededClient boundClient(final String clientId, final boolean consent) {
        final io.helixiam.authorization.amqp.client.ClientDto saved = context.getBean(
                io.helixiam.authorization.amqp.client.ClientAdminPublisher.class).create(
                new io.helixiam.authorization.amqp.client.ClientWriteDto(realm, null, clientId,
                        List.of("authorization_code", "refresh_token"), List.of(E2eSeed.REDIRECT_URI),
                        List.of("openid", "verified_claims"), null, STEP_UP_FLOW, clientId, "e2e step-up client",
                        List.of(), List.of(), false, consent, true, null, null, null, null, false, null, null, null,
                        false, null, null, null, null, null, false, false, null));
        return new E2eSeed.SeededClient(realm, saved.id(), clientId, saved.secret(), E2eSeed.REDIRECT_URI, saved);
    }

    /** The subject the login connection computes for a PID carrying {@code number}. */
    private WalletSubject numberSubject(final String number) {
        final WalletSubject.AdminNumber resolved = (WalletSubject.AdminNumber) context
                .getBean(WalletSubjectResolver.class).resolve(realm, matched(pid(number)), login.config());
        return new WalletSubject.AdminNumber(resolved.value(), null);
    }

    /** A PID with {@code number}, names, a birth date (over 18) and two nationalities. */
    private static Map<String, Object> pid(final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>(WalletE2eFixture.pidWithNumber(number));
        claims.put("nationalities", List.of("DE", "NL"));
        return claims;
    }

    /**
     * Starts {@code clientId}'s login (with {@code extra} authorize parameters), signs ada in with the first factor (a
     * federated sign-in at eIDAS substantial, the e2e broker stub), and follows to the wallet page the verification
     * step sends the browser to.
     */
    private E2eHttp.Response signInThenWalletPage(final E2eHttp browser, final OidcFlow.Pkce pkce,
                                                  final String clientId, final Map<String, String> extra) {
        final StringBuilder authorize = new StringBuilder("/realms/" + realm + "/oauth2/authorize?response_type=code"
                + "&client_id=" + clientId + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&state=st"
                + "&code_challenge=" + pkce.challenge() + "&code_challenge_method=S256");
        final Map<String, String> params = new LinkedHashMap<>(Map.of("scope", "openid verified_claims"));
        params.putAll(extra);
        params.forEach((k, v) -> authorize.append('&').append(k).append('=').append(encode(v)));
        final E2eHttp.Response loginPage = browser.followRedirects(browser.get(authorize.toString(), "Accept",
                "text/html"));
        assertThat(loginPage.uri().getPath()).as(loginPage + "\n" + browser.trail(8)).endsWith("/login");
        final E2eHttp.Response page = browser.followRedirects(browser.get("/realms/" + realm
                + "/broker/e2e-stub/complete?userId=" + ada.userId() + "&loa=" + encode(SUBSTANTIAL)));
        assertThat(page.uri().getPath()).as(page + "\n" + browser.trail(10))
                .isEqualTo("/realms/" + realm + "/broker/" + verifyAlias + "/wallet");
        return page;
    }

    private static String encode(final String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    /** The phone's wallet presents {@code claims}; returns the bound browser's {@code next} (the flow callback). */
    private String present(final E2eHttp browser, final E2eHttp.Response walletPage, final Map<String, Object> claims) {
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(walletPage.body()));
        assertThat(wallet.respond(phone, request, claims).status()).isEqualTo(200);
        final URI page = walletPage.uri();
        final String next = browser.get(page.getPath() + "/status?" + page.getRawQuery(), "Accept",
                "application/json").json().path("next").asText();
        assertThat(next).contains("/flow/wallet/callback?response_code=");
        return next;
    }

    private OidcFlow.Tokens tokens(final E2eHttp browser, final OidcFlow.Pkce pkce, final String clientId,
                                   final E2eSeed.SeededClient client, final E2eHttp.Response signedIn) {
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + browser.trail(10)).isTrue();
        return new OidcFlow(browser, realm).exchangeCode(clientId, client.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(signedIn.location()).get("code"), pkce.verifier());
    }

    private JWTClaimsSet idToken(final E2eHttp browser, final OidcFlow.Pkce pkce, final String clientId,
                                 final E2eSeed.SeededClient client, final E2eHttp.Response signedIn) {
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + browser.trail(10)).isTrue();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        return oidc.verify(oidc.exchangeCode(clientId, client.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(signedIn.location()).get("code"), pkce.verifier()).idToken());
    }

    /** The realm's users and their federated links. */
    private record Snapshot(int users, int links) {
    }

    private Snapshot snapshot() {
        final JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
        final Integer users = jdbc.queryForObject("SELECT count(*) FROM user_credentials WHERE realm_id = ?",
                Integer.class, realm);
        final Integer linked = jdbc.queryForObject("SELECT count(*) FROM federated_link WHERE user_id IN "
                + "(SELECT user_id FROM user_credentials WHERE realm_id = ?)", Integer.class, realm);
        return new Snapshot(users == null ? 0 : users, linked == null ? 0 : linked);
    }

    private List<AuditRecord> audits(final String type, final String transactionId) {
        return context.getBean(AuditLogService.class).search(new AuditQuery(realm, type, null, null, null, 0, 100))
                .items().stream()
                .filter(r -> r.detail() != null && r.detail().contains("\"transactionId\":\"" + transactionId + "\""))
                .toList();
    }

    private List<AuditRecord> awaitAudits(final String type, final String transactionId, final int count) {
        final Instant deadline = Instant.now().plusSeconds(5);
        List<AuditRecord> seen = audits(type, transactionId);
        while (seen.size() < count && Instant.now().isBefore(deadline)) {
            sleep(25);
            seen = audits(type, transactionId);
        }
        sleep(300);
        return audits(type, transactionId);
    }

    private static void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static MatchedPresentations matched(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(new VerifiedPresentation("dc+sd-jwt", "urn:eudi:pid:1",
                Map.copyOf(claims), "CN=issuer", "01", "VALID")), java.util.Set.of());
    }
}
