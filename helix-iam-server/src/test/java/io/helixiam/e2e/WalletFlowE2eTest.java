/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.SignedJWT;
import io.helixiam.authorization.federation.wallet.AuthorizationRequestFactory;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletIdentityProviders;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.federation.wallet.WalletSubjectResolver;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.federation.wallet.WalletConfigValidator;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.key.RealmSigningKeys;
import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 18: "Sign in with EUDI Wallet" end to end over real HTTP. A {@link E2eHttp} browser signs in at an OIDC client,
 * picks the wallet on the login page, and reads the wallet page; the test wallet ({@link WalletE2eFixture}) scans the
 * QR code (cross-device) or follows the "Open wallet" link (same-device), fetches the signed request object and posts
 * an encrypted PID presentation. The browser then polls the status endpoint (cross-device) or follows the
 * {@code redirect_uri} (same-device) back through the broker callback to the client with an authorization code.
 *
 * <p>Status names the page sees: {@code PENDING} (created, request fetched, response received), {@code COMPLETED}
 * (verified or redeemed), {@code FAILED}; an expired or unknown transaction, or one of another browser or realm, is a
 * bare 404.
 */
class WalletFlowE2eTest extends AbstractE2eTest {

    private static final String ALIAS_PREFIX = "eudi";

    private WalletE2eFixture wallet;
    private String realm;
    private String alias;
    private E2eSeed.SeededClient web;
    private WalletIdentityProvider provider;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("wallet");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        alias = E2eSeed.unique(ALIAS_PREFIX);
        provider = wallet.storedProvider(realm, alias, Map.of());
        wallet.install(realm, provider);
    }

    // ------------------------------------------------------------------------------------------------ happy paths

    @Test
    void crossDevice_scanThenPoll_signsInWithANewAccount() {
        final Login login = startLogin(newBrowser(), realm, alias);
        assertThat(poll(login).path("status").asText()).isEqualTo("PENDING");

        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(poll(login).path("status").asText()).as("the browser sees the wallet open the request")
                .isEqualTo("WALLET_OPENED");
        final E2eHttp.Response posted = wallet.respond(phone, request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()));

        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        assertThat(posted.json().isObject()).isTrue();
        assertThat(posted.json().size()).as("cross-device: no redirect_uri for the wallet").isZero();
        assertThat(posted.header("Content-Type").orElse("")).startsWith("application/json");

        // One poll flips the page to COMPLETED with where to go next; a second poll gets nothing new.
        final JsonNode done = poll(login);
        assertThat(done.path("status").asText()).isEqualTo("COMPLETED");
        final String next = done.path("next").asText();
        assertThat(next).matches("/realms/" + realm + "/broker/" + alias + "/callback\\?response_code=[A-Za-z0-9_-]+");
        final JsonNode again = poll(login);
        assertThat(again.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(again.has("next")).isFalse();

        final String sub = finishSignIn(login, next);
        assertThat(usersInRealm(sub)).as("the wallet created exactly one account").isEqualTo(1);
    }

    @Test
    void sameDevice_openWallet_redirectUriBringsTheBrowserBackSignedIn() {
        final String number = "PAN-" + UUID.randomUUID();
        final Login login = startLogin(newBrowser(), realm, alias);
        final String helixState = context.getBean(WalletTransactionStore.class)
                .byTransactionId(WalletE2eFixture.txId(login.pageLocation())).orElseThrow().helixState();

        // Same device: the wallet app is opened from the browser's link, and the browser is the one redirected back.
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));
        final E2eHttp.Response posted = wallet.respond(login.browser(), request, WalletE2eFixture.pidWithNumber(number));

        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        final String redirectUri = posted.json().path("redirect_uri").asText();
        assertThat(redirectUri).startsWith(baseUrl() + "/realms/" + realm + "/broker/" + alias
                + "/callback?response_code=");
        // The broker's anti-forgery state never reaches the wallet: not in the redirect_uri, not in the request.
        assertThat(OidcFlow.query(URI.create(redirectUri))).containsOnlyKeys("response_code");
        assertThat(redirectUri).doesNotContain(helixState);
        assertThat(request.claims().toString()).doesNotContain(helixState);
        assertThat(posted.body()).doesNotContain(helixState);
        final String sub = finishSignIn(login, redirectUri);

        // The same PID again (a returning user) signs in as the same account.
        final Login second = startLogin(newBrowser(), realm, alias);
        final Oid4vpWalletClient.VerifiedRequest request2 =
                WalletE2eFixture.fetchRequest(second.browser(), WalletE2eFixture.openWalletLink(second.page()));
        final E2eHttp.Response posted2 = wallet.respond(second.browser(), request2, WalletE2eFixture.pidWithNumber(number));
        // The page's poll sees the login done but gets no code: a same-device code only travels via the wallet.
        final JsonNode status = poll(second);
        assertThat(status.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(status.has("next")).isFalse();
        assertThat(finishSignIn(second, posted2.json().path("redirect_uri").asText())).isEqualTo(sub);
    }

    // ------------------------------------------------------------------------------------------------ single use

    /**
     * Conformance ruling D2: a wallet that fetches its request_uri again (a retry after a network error) gets the same
     * request object until it has posted its response. The other invocation stays dead from the first fetch on, and
     * after the response the request id is spent.
     */
    @Test
    void requestObject_canBeFetchedAgain_untilTheResponse_butOnlyThroughTheFlowThatClaimedIt() throws Exception {
        final Login login = startLogin(newBrowser(), realm, alias);
        final String invocation = WalletE2eFixture.scanQr(login.page());
        final String requestUri = Oid4vpWalletClient.invocationParameters(invocation).get("request_uri");
        final E2eHttp phone = newBrowser();

        final E2eHttp.Response first = phone.get(requestUri, "Accept", "application/oauth-authz-req+jwt");
        assertThat(first.status()).isEqualTo(200);
        assertThat(first.header("Content-Type").orElse("")).startsWith("application/oauth-authz-req+jwt");
        assertThat(first.header("Cache-Control").orElse("")).contains("no-store");

        final E2eHttp.Response again = phone.get(requestUri, "Accept", "application/oauth-authz-req+jwt");
        assertThat(again.status()).as("a re-fetch of the same request id").isEqualTo(200);
        assertThat(SignedJWT.parse(again.body()).getJWTClaimsSet().getClaims())
                .as("the same request: identical claims (nonce, state, response_uri, keys, iat, exp)")
                .isEqualTo(SignedJWT.parse(first.body()).getJWTClaimsSet().getClaims());
        // ...but the other invocation is dead from the first fetch on.
        final String sameDevice = Oid4vpWalletClient.invocationParameters(WalletE2eFixture.openWalletLink(login.page()))
                .get("request_uri");
        assertThat(phone.get(sameDevice, "Accept", "application/oauth-authz-req+jwt").status()).isEqualTo(404);

        final Oid4vpWalletClient.VerifiedRequest request = WalletE2eFixture.fetchRequest(phone, invocation);
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())).status())
                .isEqualTo(200);
        assertThat(phone.get(requestUri, "Accept", "application/oauth-authz-req+jwt").status())
                .as("after the response the request id is spent").isEqualTo(404);
    }

    @Test
    void responsePostedTwice_theSecondIsRejectedAsAReplay() {
        final Login login = startLogin(newBrowser(), realm, alias);
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        final Map<String, String> form = Map.of("response",
                Oid4vpWalletClient.respond(request, wallet.vpToken(request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()))));

        assertThat(phone.postForm(request.responseUri(), form).status()).isEqualTo(200);
        final E2eHttp.Response replay = phone.postForm(request.responseUri(), form);

        assertThat(replay.status()).isEqualTo(400);
        assertThat(replay.json().path("error").asText()).isEqualTo("invalid_request");
        assertThat(replay.json().size()).as("no detail beyond the spec error code").isEqualTo(1);
        assertThat(poll(login).path("status").asText()).as("the first response stands").isEqualTo("COMPLETED");
    }

    /** Fix round 1: starting again in the same browser discards the earlier wallet login (one live per browser). */
    @Test
    void startingAgainInTheSameBrowser_discardsTheEarlierTransaction() {
        final Login first = startLogin(newBrowser(), realm, alias);
        final Login second = startLogin(first.browser(), realm, alias);

        assertThat(first.browser().get(statusPath(first), "Accept", "application/json").status()).isEqualTo(404);
        final String firstRequest = Oid4vpWalletClient.invocationParameters(WalletE2eFixture.scanQr(first.page()))
                .get("request_uri");
        assertThat(newBrowser().get(firstRequest, "Accept", "application/oauth-authz-req+jwt").status()).isEqualTo(404);
        assertThat(poll(second).path("status").asText()).isEqualTo("PENDING");
    }

    // ------------------------------------------------------------------------------------------------ failures

    @Test
    void walletError_accessDenied_failsTheLogin_andThePageOffersARetry() {
        final Login login = startLogin(newBrowser(), realm, alias);
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

        final E2eHttp.Response posted = phone.postForm(request.responseUri(),
                Map.of("error", "access_denied", "state", request.state()));

        assertThat(posted.status()).as("a processed error response is a 200 (OpenID4VP §8.2)").isEqualTo(200);
        assertThat(posted.json().has("redirect_uri")).isFalse();
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
        final E2eHttp.Response page = login.browser().get(login.pageLocation());
        assertThat(page.body()).contains("id=\"walletRetry\"").contains("/realms/" + realm + "/broker/" + alias + "\"");
        assertThat(page.body()).doesNotContain("data:image/svg+xml");
    }

    @Test
    void wrongState_isRejected_andFailsTheTransaction() {
        final Login login = startLogin(newBrowser(), realm, alias);
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

        final E2eHttp.Response posted = phone.postForm(request.responseUri(),
                Map.of("error", "access_denied", "state", "not-the-state"));

        assertThat(posted.status()).isEqualTo(400);
        assertThat(posted.json().path("error").asText()).isEqualTo("invalid_request");
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
    }

    @Test
    void expiredTransaction_isGone_forTheStatusAndThePage() throws Exception {
        final Login login = startLogin(newBrowser(), realm, alias);
        final WalletTransactionStore store = context.getBean(WalletTransactionStore.class);
        final WalletTransaction live = store.byTransactionId(WalletE2eFixture.txId(login.pageLocation())).orElseThrow();
        // A transaction of this browser that expires one second from now (the store's minimum lifetime is 60 s).
        final Instant now = Instant.now();
        final WalletTransaction shortLived = new WalletTransaction(token(), token(), token(), token(), realm, alias,
                live.helixState(), live.browserBindingHash(), token(), live.encryptionJwkJson(), live.dcqlQueryJson(),
                null, WalletTransaction.Status.CREATED, null, null, null, now.minusSeconds(59), now.plusSeconds(1));
        store.create(shortLived);
        final String status = "/realms/" + realm + "/broker/" + alias + "/wallet/status?tx=" + shortLived.transactionId();
        assertThat(login.browser().get(status, "Accept", "application/json").status()).isEqualTo(200);

        Thread.sleep(1_500);

        final E2eHttp.Response gone = login.browser().get(status, "Accept", "application/json");
        assertThat(gone.status()).isEqualTo(404);
        assertThat(gone.body()).doesNotContain("EXPIRED").doesNotContain(shortLived.transactionId());
        final E2eHttp.Response page = login.browser().get("/realms/" + realm + "/broker/" + alias + "/wallet?tx="
                + shortLived.transactionId());
        assertThat(page.status()).isEqualTo(404);
        assertThat(page.body()).contains("expired or unknown").contains("id=\"walletRetry\"");
    }

    // ------------------------------------------------------------------------------------------------ binding

    /** Review Focus 1: the status, the page and the callback belong to the browser that started the login. */
    @Test
    void statusAndCallback_fromAnotherBrowserSession_areRefused() {
        final Login login = startLogin(newBrowser(), realm, alias);
        final E2eHttp attacker = newBrowser();
        attacker.followRedirects(attacker.get("/realms/" + realm + "/login"));

        assertThat(attacker.get(statusPath(login), "Accept", "application/json").status()).isEqualTo(404);
        assertThat(attacker.get(login.pageLocation()).status()).isEqualTo(404);

        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())).status())
                .isEqualTo(200);
        assertThat(attacker.get(statusPath(login), "Accept", "application/json").status())
                .as("another browser cannot obtain the response code").isEqualTo(404);

        final String next = poll(login).path("next").asText();
        // A stolen callback URL (code + state) is useless in another browser session...
        final E2eHttp.Response stolen = attacker.get(next);
        assertThat(stolen.status()).isEqualTo(302);
        assertThat(stolen.location().toString()).endsWith("/login?error=federation");
        // ...and does not burn the code for the browser it belongs to.
        assertThat(finishSignIn(login, next)).isNotBlank();
    }

    // ------------------------------------------------------------------------------------------------ realms

    @Test
    void endpointsOfARealmATransaction_calledUnderRealmB_are404() {
        final String realmB = E2eSeed.unique("wallet-b");
        seed().realm(realmB);
        // A YAML provider serves every realm, so only the transaction's own realm stops the cross-realm use.
        final String yamlAlias = E2eSeed.unique("eudi-yaml");
        final WalletIdentityProvider yaml = wallet.yamlProvider(yamlAlias);
        wallet.install(realm, provider, yaml);
        wallet.install(realmB, yaml); // the one YAML provider, registered for every realm
        final Login login = startLogin(newBrowser(), realm, yamlAlias);
        final String sameDevice = Oid4vpWalletClient.invocationParameters(WalletE2eFixture.openWalletLink(login.page()))
                .get("request_uri");
        final String underB = sameDevice.replace("/realms/" + realm + "/", "/realms/" + realmB + "/");
        final E2eHttp phone = newBrowser();

        assertThat(phone.get(underB, "Accept", "application/oauth-authz-req+jwt").status()).isEqualTo(404);
        assertThat(login.browser().get(statusPath(login).replace("/realms/" + realm + "/", "/realms/" + realmB + "/"),
                "Accept", "application/json").status()).isEqualTo(404);
        assertThat(login.browser().get(login.pageLocation().replace("/realms/" + realm + "/", "/realms/" + realmB + "/"))
                .status()).isEqualTo(404);

        // A stored provider of realm A is not served under realm B at all.
        final Login storedLogin = startLogin(newBrowser(), realm, alias);
        final String storedUnderB = Oid4vpWalletClient.invocationParameters(WalletE2eFixture.scanQr(storedLogin.page()))
                .get("request_uri").replace("/realms/" + realm + "/", "/realms/" + realmB + "/");
        assertThat(phone.get(storedUnderB, "Accept", "application/oauth-authz-req+jwt").status()).isEqualTo(404);
        final E2eHttp.Response response = phone.postForm(baseUrl() + "/realms/" + realmB + "/oid4vp/" + alias
                + "/response/whatever", Map.of("error", "access_denied", "state", "x"));
        assertThat(response.status()).isEqualTo(404);

        // ...and does not start a login there (Task 19).
        final E2eHttp other = newBrowser();
        other.followRedirects(other.get("/realms/" + realmB + "/login"));
        final E2eHttp.Response start = other.get("/realms/" + realmB + "/broker/" + alias);
        assertThat(start.location().toString()).endsWith("/login?error=federation");
    }

    // ------------------------------------------------------------------------------------------------ limits

    @Test
    void aResponseBodyOver256KiB_isRefusedWith413() {
        final E2eHttp phone = newBrowser();
        final byte[] body = ("response=" + "a".repeat(300 * 1024)).getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        final E2eHttp.Response tooBig = phone.postBytes(baseUrl() + "/realms/" + realm + "/oid4vp/" + alias
                + "/response/some-response-id", "application/x-www-form-urlencoded", body);

        assertThat(tooBig.status()).isEqualTo(413);
    }

    /**
     * Fix round 2: through the real filter chain, a PUT form to the response endpoint is refused with 405 before any
     * filter reads its body. The body is a form that cannot be decoded ({@code %zz}): Spring's FormContentFilter, which
     * parses PUT forms, would fail on it with a 4xx/5xx of its own if it ran first, so the wallet filter's exact 405
     * answer proves it runs before every body reader (the method cannot bypass the body limit).
     */
    @Test
    void aPutFormToTheResponseEndpoint_is405_beforeItsBodyIsRead() throws Exception {
        final java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .version(java.net.http.HttpClient.Version.HTTP_1_1).build();
        final String url = baseUrl() + "/realms/" + realm + "/oid4vp/" + alias + "/response/some-id";

        final java.net.http.HttpResponse<String> put = client.send(java.net.http.HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .method("PUT", java.net.http.HttpRequest.BodyPublishers.ofString("response=%zz"))
                .build(), java.net.http.HttpResponse.BodyHandlers.ofString());

        assertThat(put.statusCode()).isEqualTo(405);
        assertThat(put.headers().firstValue("Allow")).contains("GET, POST");
        assertThat(put.body()).isEqualTo("{\"error\":\"invalid_request\"}");

        // Control: the same undecodable form PUT elsewhere is read (and refused) by Spring's FormContentFilter.
        final java.net.http.HttpResponse<String> elsewhere = client.send(java.net.http.HttpRequest.newBuilder(
                        URI.create(baseUrl() + "/realms/" + realm + "/login"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .method("PUT", java.net.http.HttpRequest.BodyPublishers.ofString("response=%zz"))
                .build(), java.net.http.HttpResponse.BodyHandlers.ofString());
        assertThat(elsewhere.statusCode()).as(elsewhere.body()).isNotEqualTo(405);
        assertThat(elsewhere.body()).doesNotContain("invalid_request");
    }

    @Test
    void walletEndpoints_needNoCsrfToken_butOtherPostsStillDo() {
        final E2eHttp phone = newBrowser();
        final E2eHttp.Response wallet = phone.postForm(baseUrl() + "/realms/" + realm + "/oid4vp/" + alias
                + "/response/unknown-response-id", Map.of("error", "access_denied", "state", "x"));
        assertThat(wallet.status()).as("no CSRF 403: the endpoint itself answered").isEqualTo(400);
        assertThat(wallet.json().path("error").asText()).isEqualTo("invalid_request");

        final E2eHttp browser = newBrowser();
        browser.followRedirects(browser.get("/realms/" + realm + "/login"));
        final E2eHttp.Response noToken = browser.postForm("/realms/" + realm + "/login",
                Map.of("username", "nobody", "password", "nothing"));
        assertThat(noToken.status()).as("CSRF is still enforced elsewhere: " + noToken).isEqualTo(403);
    }

    @Test
    void aFullTransactionStore_showsAFriendly503() {
        final WalletTransactionStore full = new InMemoryWalletTransactionStore(Clock.systemUTC(), 1);
        final WalletIdentityProviders builder = new WalletIdentityProviders(context.getBean(WalletConfigValidator.class),
                context.getBean(RealmSigningKeys.class), full, new OutboundUrlGuard(), context.getBean(AuditLog.class));
        final String fullAlias = E2eSeed.unique("eudi-full");
        final WalletIdentityProvider fullProvider = builder.build(realm, WalletProviderConfig.fromStored(fullAlias,
                "Wallet", wallet.storedConfig(wallet.importAccessKey(realm))));
        wallet.install(realm, provider, fullProvider);
        final E2eHttp first = newBrowser();
        first.followRedirects(first.get("/realms/" + realm + "/login"));
        assertThat(first.get("/realms/" + realm + "/broker/" + fullAlias).location().getPath()).endsWith("/wallet");

        final E2eHttp second = newBrowser();
        second.followRedirects(second.get("/realms/" + realm + "/login"));
        final E2eHttp.Response busy = second.followRedirects(second.get("/realms/" + realm + "/broker/" + fullAlias));

        assertThat(busy.status()).isEqualTo(503);
        assertThat(busy.body()).contains("id=\"walletRetry\"").doesNotContain("Exception");
    }

    // ------------------------------------------------------------------------------------------------ accounts

    @Test
    void aTupleOnlyWallet_withoutALink_isSentToTheLinkExplanation() {
        final String tupleAlias = E2eSeed.unique("eudi-tuple");
        wallet.install(realm, wallet.storedProvider(realm, tupleAlias, Map.of("subject.acknowledgeWeakSubject", "true")));
        final Login login = startLogin(newBrowser(), realm, tupleAlias);
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithoutNumber()).status()).isEqualTo(200);

        final String next = poll(login).path("next").asText();
        final E2eHttp.Response landed = login.browser().followRedirects(login.browser().get(next));

        assertThat(landed.status()).isEqualTo(200);
        assertThat(landed.body()).contains("id=\"walletLinkRequired\"");
        assertThat(landed.body()).doesNotContain("Erika").doesNotContain("Mustermann");
        assertThat(countUsersCreatedSince(realm)).isZero();
    }

    /** A JIT race: two logins with the same unlinked number both provision; the loser must not leave an orphan. */
    @Test
    void twoLoginsRacingToProvisionTheSameNumber_leaveOneAccountAndNoOrphan() {
        final String number = "PAN-" + UUID.randomUUID();
        // A: verified (decision Provision stored) but not redeemed yet.
        final Login a = startLogin(newBrowser(), realm, alias);
        final E2eHttp phoneA = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest requestA =
                WalletE2eFixture.fetchRequest(phoneA, WalletE2eFixture.scanQr(a.page()));
        assertThat(wallet.respond(phoneA, requestA, WalletE2eFixture.pidWithNumber(number)).status()).isEqualTo(200);
        final String nextA = poll(a).path("next").asText();

        // B: the same number completes first and creates the account.
        final Login b = startLogin(newBrowser(), realm, alias);
        final E2eHttp phoneB = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest requestB =
                WalletE2eFixture.fetchRequest(phoneB, WalletE2eFixture.scanQr(b.page()));
        assertThat(wallet.respond(phoneB, requestB, WalletE2eFixture.pidWithNumber(number)).status()).isEqualTo(200);
        final String winner = finishSignIn(b, poll(b).path("next").asText());
        final long usersAfterB = countUsersCreatedSince(realm);

        // A now provisions too, loses the link, signs in as B's account and removes its own fresh user.
        assertThat(finishSignIn(a, nextA)).isEqualTo(winner);
        assertThat(countUsersCreatedSince(realm)).as("no orphan account").isEqualTo(usersAfterB);
    }

    /**
     * The upgrade link (a number seen on a tuple-linked account) is committed only once the login has succeeded. Here
     * the login fails after the account was resolved: another account claims the number between the verification and
     * the browser's callback, so the commit is refused, the login ends without a session, and the number is not
     * re-linked to the tuple's account. (The step-up variant is covered by FederatedLoginCompleterPendingCommitTest and
     * FlowControllerPendingCommitTest.)
     */
    @Test
    void thePendingNumberLink_isNotCommitted_whenTheLoginFailsAfterResolution() {
        final String upgradeAlias = E2eSeed.unique("eudi-upgrade");
        final WalletIdentityProvider upgrade = wallet.storedProvider(realm, upgradeAlias,
                Map.of("subject.acknowledgeWeakSubject", "true"));
        wallet.install(realm, provider, upgrade);
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), "Wallet-Upgrade-Passw0rd-2026!");
        final E2eSeed.SeededUser bob = seed().user(realm, E2eSeed.unique("bob"), "Wallet-Upgrade-Passw0rd-2026!");
        final WalletLinkService links = context.getBean(WalletLinkService.class);
        final WalletSubjectResolver resolver = context.getBean(WalletSubjectResolver.class);
        final String number = "PAN-" + UUID.randomUUID();
        final WalletSubject tuple = resolver.resolve(realm, matched(WalletE2eFixture.pidWithoutNumber()), upgrade.config());
        assertThat(links.link(realm, ada.userId(), upgradeAlias, tuple)).isEqualTo(WalletLinkService.LinkResult.LINKED);
        final WalletSubject.AdminNumber numberSubject = new WalletSubject.AdminNumber(((WalletSubject.AdminNumber)
                resolver.resolve(realm, matched(WalletE2eFixture.pidWithNumber(number)), upgrade.config())).value(), null);

        final Login login = startLogin(newBrowser(), realm, upgradeAlias);
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(wallet.respond(phone, request, WalletE2eFixture.pidWithNumber(number)).status()).isEqualTo(200);
        final String next = poll(login).path("next").asText();
        assertThat(links.find(realm, upgradeAlias, numberSubject)).as("nothing committed at verification").isEmpty();

        // Resolved to ada (tuple) with a pending number link; meanwhile bob's account claims the number.
        assertThat(links.link(realm, bob.userId(), upgradeAlias, numberSubject))
                .isEqualTo(WalletLinkService.LinkResult.LINKED);
        final E2eHttp.Response callback = login.browser().followRedirectsUntil(login.browser().get(next),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI) || r.location() != null
                        && r.location().getPath().endsWith("/login"));

        assertThat(callback.location().toString()).as(callback.toString()).endsWith("/login?error=federation");
        assertThat(links.find(realm, upgradeAlias, numberSubject)).contains(bob.userId());
        assertThat(links.find(realm, upgradeAlias, tuple)).contains(ada.userId());
        // ...and the browser is not signed in: authorizing again ends on the login page, not at the client.
        final E2eHttp.Response again = login.browser().followRedirectsUntil(login.browser().get("/realms/" + realm
                + "/oauth2/authorize?response_type=code&client_id=web&redirect_uri=" + E2eSeed.REDIRECT_URI
                + "&scope=openid&state=x&code_challenge=" + login.pkce().challenge() + "&code_challenge_method=S256",
                "Accept", "text/html"), r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(again.locationStartsWith(E2eSeed.REDIRECT_URI)).as(again.toString()).isFalse();
        assertThat(again.uri().getPath()).endsWith("/login");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private record Login(E2eHttp browser, OidcFlow.Pkce pkce, String pageLocation, String page) {
    }

    private Login startLogin(final E2eHttp browser, final String realmId, final String providerAlias) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realmId + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        final E2eHttp.Response loginPage = browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        assertThat(loginPage.body()).contains("/broker/" + providerAlias);
        final E2eHttp.Response start = browser.get("/realms/" + realmId + "/broker/" + providerAlias);
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        assertThat(location.getPath()).isEqualTo("/realms/" + realmId + "/broker/" + providerAlias + "/wallet");
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = browser.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        return new Login(browser, pkce, pageLocation, page.body());
    }

    private String statusPath(final Login login) {
        final String tx = WalletE2eFixture.txId(login.pageLocation());
        return login.pageLocation().substring(0, login.pageLocation().indexOf("?")) + "/status?tx=" + tx;
    }

    private JsonNode poll(final Login login) {
        final E2eHttp.Response status = login.browser().get(statusPath(login), "Accept", "application/json");
        assertThat(status.status()).as(status.toString()).isEqualTo(200);
        assertThat(status.header("Cache-Control").orElse("")).contains("no-store");
        return status.json();
    }

    /** Follows the callback to the client, redeems the code and returns the ID token subject. */
    private String finishSignIn(final Login login, final String callback) {
        final E2eHttp http = login.browser();
        final E2eHttp.Response signedIn = http.followRedirectsUntil(http.get(callback),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI)).as(signedIn + "\n" + http.trail(10)).isTrue();
        final String code = OidcFlow.query(signedIn.location()).get("code");
        final OidcFlow oidc = new OidcFlow(http, realm);
        final OidcFlow.Tokens tokens = oidc.exchangeCode("web", web.secret(), E2eSeed.REDIRECT_URI, code,
                login.pkce().verifier());
        try {
            final var id = oidc.verify(tokens.idToken());
            assertThat(id.getStringClaim("acr")).isEqualTo("http://eidas.europa.eu/LoA/high");
            return id.getSubject();
        } catch (final java.text.ParseException e) {
            throw new AssertionError(e);
        }
    }

    private long usersInRealm(final String userId) {
        return context.getBean(JdbcTemplate.class).queryForObject(
                "SELECT count(*) FROM tenant_user WHERE tenant_id = ? AND user_id = ?", Long.class, realm, userId);
    }

    /** Users of the realm other than its bootstrapped admin and seeded ones (wallet-provisioned accounts). */
    private long countUsersCreatedSince(final String realmId) {
        return context.getBean(JdbcTemplate.class).queryForObject(
                "SELECT count(*) FROM user_credentials WHERE realm_id = ? AND password IS NULL", Long.class, realmId);
    }

    private static MatchedPresentations matched(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(new VerifiedPresentation("dc+sd-jwt", "urn:eudi:pid:1",
                Map.copyOf(claims), "CN=issuer", "01", "VALID")), java.util.Set.of());
    }

    private static String token() {
        return AuthorizationRequestFactory.walletState(UUID.randomUUID().toString());
    }
}
