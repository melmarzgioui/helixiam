/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.helixiam.authorization.federation.wallet.testwallet.DcApiWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.net.URI;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * OpenID4VP over the W3C Digital Credentials API end to end over real HTTP, in the style of {@link WalletFlowE2eTest}.
 * A {@link E2eHttp} browser signs in at an OIDC client and opens the wallet page; it plays the page script
 * ({@code wallet-dcapi.js}): POST the request endpoint with the page's CSRF token, hand {@code {protocol, data}} to the
 * test wallet ({@link DcApiWalletClient}, standing in for {@code navigator.credentials.get} with the page's origin),
 * POST the {@code DigitalCredential} back, and follow {@code next} through the broker callback to the client.
 */
class WalletDcApiFlowE2eTest extends AbstractE2eTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern DC_API_SECTION = Pattern.compile("<section id=\"walletDcApi\"([^>]*)>");

    private WalletE2eFixture wallet;
    private String realm;
    private String alias;
    private E2eSeed.SeededClient web;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("wallet-dcapi");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        alias = E2eSeed.unique("eudi");
        wallet.install(realm, wallet.storedProviderBothFormats(realm, alias, Map.of("dcApi.enabled", "true")));
    }

    /** The page's origin as the browser serialises it: what the platform hands the wallet. */
    private static String origin() {
        final URI base = URI.create(baseUrl());
        return base.getScheme() + "://" + base.getHost() + (base.getPort() == -1 ? "" : ":" + base.getPort());
    }

    // ------------------------------------------------------------------------------------------------ happy paths

    @Test
    void signedRequest_sdJwt_signsInWithANewAccount() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();
        assertThat(page.protocol()).isEqualTo("openid4vp-v1-signed");

        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        assertThat(request.claims()).containsEntry("expected_origins", List.of(origin()))
                .containsEntry("response_mode", "dc_api.jwt").doesNotContainKeys("response_uri", "state");
        assertThat(poll(login).path("status").asText()).as("asking for the request changes nothing")
                .isEqualTo("PENDING");

        final E2eHttp.Response posted = post(login, page.responseUrl(), body(request,
                sdJwtVpToken(request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()))));

        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        assertThat(posted.header("Cache-Control").orElse("")).contains("no-store");
        assertThat(posted.json().path("status").asText()).isEqualTo("COMPLETED");
        final String next = posted.json().path("next").asText();
        assertThat(next).matches("/realms/" + realm + "/broker/" + alias + "/callback\\?response_code=[A-Za-z0-9_-]+");
        assertThat(poll(login).has("next")).as("the code went to the page already").isFalse();
        assertThat(store().byTransactionId(login.txId()).orElseThrow().flow()).isEqualTo(WalletTransaction.Flow.DC_API);

        final String sub = finishSignIn(login, next);
        assertThat(context.getBean(JdbcTemplate.class).queryForObject(
                "SELECT count(*) FROM tenant_user WHERE tenant_id = ? AND user_id = ?", Long.class, realm, sub))
                .isEqualTo(1);
    }

    @Test
    void unsignedRequest_mdoc_signsIn() {
        final String unsigned = E2eSeed.unique("eudi-unsigned");
        wallet.install(realm, wallet.storedProviderBothFormats(realm, unsigned,
                Map.of("dcApi.enabled", "true", "dcApi.request", "unsigned")));
        final Login login = startLogin(newBrowser(), unsigned);
        final Page page = login.dcApi();
        assertThat(page.protocol()).isEqualTo("openid4vp-v1-unsigned");

        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        assertThat(request.clientId()).isNull();
        final E2eHttp.Response posted = post(login, page.responseUrl(), body(request, mdocVpToken(request)));

        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        assertThat(finishSignIn(login, posted.json().path("next").asText())).isNotBlank();
    }

    // ------------------------------------------------------------------------------------------------ refusals

    @Test
    void aPresentationBoundToAnotherOrigin_isRefused_andTheLoginFails() {
        final String unsigned = E2eSeed.unique("eudi-unsigned");
        wallet.install(realm, wallet.storedProviderBothFormats(realm, unsigned,
                Map.of("dcApi.enabled", "true", "dcApi.request", "unsigned")));
        final Login login = startLogin(newBrowser(), unsigned);
        final Page page = login.dcApi();
        // An unsigned request relayed by a phishing page: the wallet binds its answer to that page's origin.
        final DcApiWalletClient.DcApiRequest atEvil = fetchRequest(login, page, "https://evil.example.com");

        final E2eHttp.Response posted = post(login, page.responseUrl(), body(atEvil,
                sdJwtVpToken(atEvil, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()))));

        assertThat(posted.status()).isEqualTo(400);
        assertThat(posted.json().path("status").asText()).isEqualTo("FAILED");
        assertThat(posted.json().path("reason").asText()).isEqualTo("not_accepted");
        assertThat(posted.body()).doesNotContain("AUDIENCE").doesNotContain("origin");
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
    }

    @Test
    void aSignedRequest_isRefusedByTheWallet_atAnotherOrigin() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();
        final E2eHttp.Response response = post(login, page.requestUrl(), null);

        assertThat(response.status()).isEqualTo(200);
        final Map<String, Object> data = JSON.convertValue(response.json().path("data"), new TypeReference<>() { });
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> DcApiWalletClient.verify(page.protocol(), data,
                "https://evil.example.com", Instant.now())).hasMessageContaining("expected_origins");
    }

    @Test
    void theSameResponsePostedTwice_isAReplay() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();
        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        final Map<String, Object> body = body(request,
                sdJwtVpToken(request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())));

        assertThat(post(login, page.responseUrl(), body).status()).isEqualTo(200);
        final E2eHttp.Response replay = post(login, page.responseUrl(), body);

        assertThat(replay.status()).isEqualTo(400);
        assertThat(replay.json().path("reason").asText()).isEqualTo("technical");
        assertThat(replay.json().has("next")).isFalse();
        assertThat(poll(login).path("status").asText()).as("the first answer stands").isEqualTo("COMPLETED");
    }

    @Test
    void anotherBrowser_cannotAskForTheRequest_norPostTheResponse() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();
        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        final Map<String, Object> body = body(request,
                sdJwtVpToken(request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())));

        final E2eHttp attacker = newBrowser();
        final E2eHttp.Response loginPage = attacker.followRedirects(attacker.get("/realms/" + realm + "/login"));
        assertThat(loginPage.status()).isEqualTo(200);
        final String[] csrf = attacker.xsrfHeader();
        assertThat(attacker.sendJson("POST", page.requestUrl(), "", csrf).status()).isEqualTo(404);
        assertThat(attacker.sendJson("POST", page.responseUrl(), body, csrf).status()).isEqualTo(404);

        assertThat(poll(login).path("status").asText()).as("untouched").isEqualTo("PENDING");
        assertThat(post(login, page.responseUrl(), body).status()).isEqualTo(200);
    }

    @Test
    void withoutTheCsrfToken_bothEndpointsAre403() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();

        assertThat(login.browser().sendJson("POST", page.requestUrl(), "").status()).isEqualTo(403);
        assertThat(login.browser().sendJson("POST", page.responseUrl(), Map.of("protocol", page.protocol(),
                "data", Map.of("error", "access_denied"))).status()).isEqualTo(403);
        assertThat(poll(login).path("status").asText()).isEqualTo("PENDING");
    }

    @Test
    void aCancelledBrowserSheet_leavesTheQrCodeWorking() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();
        fetchRequest(login, page, origin()); // ...and the user closes the browser's wallet chooser

        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest qr =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(wallet.respond(phone, qr, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID())).status())
                .isEqualTo(200);

        final JsonNode done = poll(login);
        assertThat(done.path("status").asText()).isEqualTo("COMPLETED");
        assertThat(post(login, page.requestUrl(), null).status()).as("the DC API is spent now").isEqualTo(404);
        assertThat(finishSignIn(login, done.path("next").asText())).isNotBlank();
    }

    @Test
    void aWalletThatAlreadyFetchedTheQrRequest_blocksTheDcApi() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();
        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        WalletE2eFixture.fetchRequest(newBrowser(), WalletE2eFixture.scanQr(login.page()));

        final E2eHttp.Response posted = post(login, page.responseUrl(), body(request,
                sdJwtVpToken(request, WalletE2eFixture.pidWithNumber("PAN-" + UUID.randomUUID()))));

        assertThat(posted.status()).isEqualTo(400);
        assertThat(poll(login).path("status").asText()).isEqualTo("WALLET_OPENED");
    }

    @Test
    void aWalletError_failsTheLogin_asDeclined() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();

        final E2eHttp.Response posted = post(login, page.responseUrl(),
                Map.of("protocol", page.protocol(), "data", Map.of("error", "access_denied")));

        assertThat(posted.status()).isEqualTo(200);
        assertThat(posted.json().path("status").asText()).isEqualTo("FAILED");
        assertThat(posted.json().path("reason").asText()).isEqualTo("declined");
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
    }

    @Test
    void aResponseBodyOverTheLimit_is413() {
        final Login login = startLogin(newBrowser(), alias);
        final Page page = login.dcApi();

        final E2eHttp.Response tooBig = login.browser().postBytes(page.responseUrl(), "application/json",
                ("{\"protocol\":\"x\",\"data\":{\"response\":\"" + "a".repeat(300 * 1024) + "\"}}")
                        .getBytes(java.nio.charset.StandardCharsets.US_ASCII), page.csrfHeader(), page.csrfToken());

        assertThat(tooBig.status()).isEqualTo(413);
        assertThat(poll(login).path("status").asText()).isEqualTo("PENDING");
    }

    @Test
    void aProviderWithoutTheDcApi_offersNothing_andItsEndpointsAre404() {
        final String plain = E2eSeed.unique("eudi-plain");
        wallet.install(realm, wallet.storedProviderBothFormats(realm, plain, Map.of()));
        final Login login = startLogin(newBrowser(), plain);

        assertThat(login.page()).doesNotContain("walletDcApi").doesNotContain("wallet-dcapi.js");
        final String base = login.pageLocation().substring(0, login.pageLocation().indexOf('?'));
        assertThat(login.browser().sendJson("POST", base + "/dc-api/request?tx=" + login.txId(), "",
                login.browser().xsrfHeader()).status()).isEqualTo(404);
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private record Page(String requestUrl, String responseUrl, String protocol, String csrfHeader, String csrfToken) {
    }

    private record Login(E2eHttp browser, OidcFlow.Pkce pkce, String pageLocation, String page) {

        String txId() {
            return WalletE2eFixture.txId(pageLocation);
        }

        /** The #walletDcApi section's data attributes, as wallet-dcapi.js reads them. */
        Page dcApi() {
            final Matcher m = DC_API_SECTION.matcher(page);
            assertThat(m.find()).as("no #walletDcApi section on the page").isTrue();
            final String attrs = m.group(1);
            assertThat(attrs).contains("hidden");
            return new Page(attr(attrs, "data-request-url"), attr(attrs, "data-response-url"),
                    attr(attrs, "data-protocol"), attr(attrs, "data-csrf-header"), attr(attrs, "data-csrf-token"));
        }

        private static String attr(final String attrs, final String name) {
            final Matcher m = Pattern.compile(name + "=\"([^\"]*)\"").matcher(attrs);
            assertThat(m.find()).as(name).isTrue();
            return m.group(1).replace("&amp;", "&");
        }
    }

    private Login startLogin(final E2eHttp browser, final String providerAlias) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + providerAlias);
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = browser.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        return new Login(browser, pkce, pageLocation, page.body());
    }

    /** POST with the page's CSRF header, as wallet-dcapi.js does; a null body is an empty POST. */
    private static E2eHttp.Response post(final Login login, final String url, final Object body) {
        final Page page = login.dcApi();
        return login.browser().sendJson("POST", url, body == null ? "" : body, "Accept", "application/json",
                page.csrfHeader(), page.csrfToken());
    }

    /** The page asks for the request; the platform hands it to the wallet with {@code origin}. */
    private static DcApiWalletClient.DcApiRequest fetchRequest(final Login login, final Page page,
                                                               final String origin) {
        final E2eHttp.Response response = post(login, page.requestUrl(), null);
        assertThat(response.status()).as(response.toString()).isEqualTo(200);
        assertThat(response.header("Cache-Control").orElse("")).contains("no-store");
        assertThat(response.json().path("protocol").asText()).isEqualTo(page.protocol());
        final Map<String, Object> data = JSON.convertValue(response.json().path("data"), new TypeReference<>() { });
        return DcApiWalletClient.verify(page.protocol(), data, origin, Instant.now());
    }

    private static Map<String, Object> body(final DcApiWalletClient.DcApiRequest request, final Object vpToken) {
        final Map<String, Object> body = new LinkedHashMap<>();
        body.put("protocol", request.protocol());
        body.put("data", DcApiWalletClient.respond(request, vpToken));
        return body;
    }

    private Map<String, Object> sdJwtVpToken(final DcApiWalletClient.DcApiRequest request,
                                             final Map<String, Object> claims) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential pid = wallet.wallet().sdJwtPid(claims, now.minusSeconds(3600),
                now.plusSeconds(3600), Optional.empty());
        return Map.of("pid_sd_jwt", List.of(wallet.wallet().present(pid, claims.keySet(), request.audience(),
                request.nonce())));
    }

    private Map<String, Object> mdocVpToken(final DcApiWalletClient.DcApiRequest request) {
        final Instant now = Instant.now();
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birth_date", new TestWallet.CborTag(1004, "1984-01-26"));
        claims.put("issuing_country", "DE");
        claims.put("personal_administrative_number", "PAN-" + UUID.randomUUID());
        final TestWallet.MdocCredential credential = wallet.wallet().mdocPid(claims, now.minusSeconds(3600),
                now.minusSeconds(3600), now.plusSeconds(3600), Optional.empty());
        return Map.of("pid_mdoc", List.of(TestWallet.b64url(TestWallet.mdocDeviceResponse(credential,
                claims.keySet(), request.sessionTranscript()))));
    }

    private WalletTransactionStore store() {
        return context.getBean(WalletTransactionStore.class);
    }

    private JsonNode poll(final Login login) {
        final String status = login.pageLocation().substring(0, login.pageLocation().indexOf('?')) + "/status?tx="
                + login.txId();
        final E2eHttp.Response response = login.browser().get(status, "Accept", "application/json");
        assertThat(response.status()).as(response.toString()).isEqualTo(200);
        return response.json();
    }

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
}
