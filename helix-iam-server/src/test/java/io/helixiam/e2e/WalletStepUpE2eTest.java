/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import io.helixiam.authorization.amqp.flow.FlowAdminPublisher;
import io.helixiam.authorization.amqp.flow.FlowExecutionDto;
import io.helixiam.authorization.amqp.flow.FlowSaveDto;
import io.helixiam.authorization.domain.audit.AuditQuery;
import io.helixiam.authorization.domain.audit.AuditRecord;
import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.federation.wallet.WalletSubjectResolver;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.service.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Final review F2: a wallet login of a user with MFA enabled goes through the post-broker step-up ({@code /flow}). The
 * login is audited once, when the step-up completes — {@code WALLET_LOGIN_SUCCESS} with the transaction id, actor the
 * signed-in user — never while it is still pending; the ID token carries the wallet's {@code acr}; and the upgrade
 * link (the number seen on a tuple-linked account) is committed only after the step-up.
 */
class WalletStepUpE2eTest extends AbstractE2eTest {

    private static final String PASSWORD = "Wallet-StepUp-Passw0rd-2026!";

    private WalletE2eFixture wallet;
    private String realm;
    private E2eSeed.SeededClient web;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("wstep");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
    }

    @Test
    void anMfaEnabledUser_stepsUp_isAuditedOnceOnCompletion_getsAcrHigh_andTheUpgradeLinkIsCommittedAfterwards() {
        final String alias = E2eSeed.unique("eudi-stepup");
        final WalletIdentityProvider provider = wallet.storedProvider(realm, alias,
                Map.of("subject.acknowledgeWeakSubject", "true"));
        wallet.install(realm, provider);
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final String secret = enableMfa(ada.userId());
        requireOtpAfterTheFirstFactor();
        // ada's wallet is linked by the attribute tuple; this login presents the number too (an upgrade link).
        final WalletLinkService links = context.getBean(WalletLinkService.class);
        final WalletSubjectResolver resolver = context.getBean(WalletSubjectResolver.class);
        final String number = "PAN-" + UUID.randomUUID();
        final WalletSubject tuple = resolver.resolve(realm, matched(WalletE2eFixture.pidWithoutNumber()), provider.config());
        assertThat(links.link(realm, ada.userId(), alias, tuple)).isEqualTo(WalletLinkService.LinkResult.LINKED);
        final WalletSubject numberSubject = new WalletSubject.AdminNumber(((WalletSubject.AdminNumber)
                resolver.resolve(realm, matched(WalletE2eFixture.pidWithNumber(number)), provider.config())).value(), null);

        final E2eHttp browser = newBrowser();
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String pageLocation = startLogin(browser, pkce, alias);
        final String tx = WalletE2eFixture.txId(pageLocation);
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(browser.get(pageLocation).body()));
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithNumber(number)).status()).isEqualTo(200);
        final String next = browser.get(pageLocation.substring(0, pageLocation.indexOf('?')) + "/status?tx=" + tx,
                "Accept", "application/json").json().path("next").asText();

        // The callback signs ada in only as far as the step-up.
        final E2eHttp.Response challenge = browser.followRedirects(browser.get(next));
        assertThat(challenge.uri().getPath()).as(challenge + "\n" + browser.trail(10))
                .isEqualTo("/realms/" + realm + "/flow");
        assertThat(links.find(realm, alias, numberSubject)).as("no upgrade link before the step-up").isEmpty();
        settle();
        assertThat(audits("WALLET_LOGIN_SUCCESS", tx)).as("not audited while pending").isEmpty();
        assertThat(audits("WALLET_LOGIN_FAILURE", tx)).isEmpty();

        // The second factor completes the login.
        final E2eHttp.Response signedIn = browser.followRedirectsUntil(browser.postForm("/realms/" + realm + "/flow",
                Map.of("_csrf", E2eHttp.csrf(challenge.body()), "code", totp(secret))),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + browser.trail(10)).isTrue();
        final OidcFlow oidc = new OidcFlow(browser, realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(signedIn.location()).get("code"), pkce.verifier());
        try {
            final var id = oidc.verify(tokens.idToken());
            assertThat(id.getSubject()).isEqualTo(ada.userId());
            assertThat(id.getStringClaim("acr")).isEqualTo("http://eidas.europa.eu/LoA/high");
        } catch (final java.text.ParseException e) {
            throw new AssertionError(e);
        }

        assertThat(links.find(realm, alias, numberSubject)).as("upgrade link committed after the step-up")
                .contains(ada.userId());
        final List<AuditRecord> success = awaitAudits("WALLET_LOGIN_SUCCESS", tx, 1);
        assertThat(success).hasSize(1);
        assertThat(success.get(0).actor()).isEqualTo(ada.userId());
        assertThat(success.get(0).detail()).contains("\"alias\":\"" + alias + "\"").contains("\"format\":\"dc+sd-jwt\"")
                .contains("\"issuerDn\":");
        assertThat(audits("WALLET_LOGIN_FAILURE", tx)).isEmpty();
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** Turns TOTP on for {@code userId} with a fresh secret, as an enrolment would; returns the secret. */
    private String enableMfa(final String userId) {
        final String secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
        final UserCredentialsRepository users = context.getBean(UserCredentialsRepository.class);
        new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(status -> {
            final UserCredentials user = users.findById(userId).orElseThrow();
            user.setMfaSecret(secret);
            user.setMfaEnabled(true);
            users.save(user);
        });
        return secret;
    }

    /**
     * The realm's browser flow: a REQUIRED one-time password after the first factor (the broker login, here), so the
     * wallet login always steps up.
     */
    private void requireOtpAfterTheFirstFactor() {
        context.getBean(FlowAdminPublisher.class).save(new FlowSaveDto(realm, "browser",
                List.of(new FlowExecutionDto("stepup-otp", null, "otp", "REQUIRED", false, 10))));
    }

    private static String totp(final String secret) {
        try {
            return TimeBasedOneTimePasswordUtil.generateCurrentNumberString(secret);
        } catch (final java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Starts a wallet login at the {@code web} client; returns the wallet page's location. */
    private String startLogin(final E2eHttp browser, final OidcFlow.Pkce pkce, final String alias) {
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        assertThat(browser.followRedirects(browser.get(authorize, "Accept", "text/html")).body())
                .contains("/broker/" + alias);
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + alias);
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        return location.getPath() + "?" + location.getRawQuery();
    }

    private List<AuditRecord> audits(final String type, final String transactionId) {
        return context.getBean(AuditLogService.class).search(new AuditQuery(realm, type, null, null, null, 0, 100))
                .items().stream()
                .filter(r -> r.detail() != null && r.detail().contains("\"transactionId\":\"" + transactionId + "\""))
                .toList();
    }

    /** Audit persistence is off the request thread: waits until {@code count} records of {@code type} are there. */
    private List<AuditRecord> awaitAudits(final String type, final String transactionId, final int count) {
        final Instant deadline = Instant.now().plusSeconds(5);
        List<AuditRecord> seen = audits(type, transactionId);
        while (seen.size() < count && Instant.now().isBefore(deadline)) {
            sleep(25);
            seen = audits(type, transactionId);
        }
        settle();
        return audits(type, transactionId);
    }

    /** Gives an (unwanted) asynchronous audit write time to land before asserting its absence. */
    private static void settle() {
        sleep(300);
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
