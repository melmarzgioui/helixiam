/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
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
import io.helixiam.authorization.federation.wallet.testwallet.DcApiWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.service.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
 * pentest-b gap: no e2e test drove a verify-only step-up ({@code subject.strategy=NONE}) through the W3C Digital
 * Credentials API to {@code /flow/wallet/callback}. Modelled on {@link WalletVerifyOnlyE2eTest} (the step-up flow:
 * {@code bank} runs a federated first factor, then {@code wallet-verify} to the {@code verifyAlias} connection,
 * then {@code /flow/wallet/callback?response_code=...}) and {@link WalletDcApiFlowE2eTest} (the DC API script's own
 * request/response endpoints, read from the page's {@code #walletDcApi} section, {@link DcApiWalletClient} standing
 * in for {@code navigator.credentials.get}).
 */
class WalletVerifyDcApiE2eTest extends AbstractE2eTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern DC_API_SECTION = Pattern.compile("<section id=\"walletDcApi\"([^>]*)>");
    private static final String PASSWORD = "Wallet-Verify-Dc-Passw0rd-2026!";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    private static final String STEP_UP_FLOW = "wallet-stepup-dcapi";

    private WalletE2eFixture wallet;
    private String realm;
    private String loginAlias;
    private String verifyAlias;
    private WalletIdentityProvider login;
    private WalletLinkService links;
    private E2eSeed.SeededUser ada;
    private String adaNumber;
    private String bobNumber;
    private E2eSeed.SeededClient bank;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("wverifydc");
        seed().realm(realm);
        loginAlias = E2eSeed.unique("eudi-login");
        verifyAlias = E2eSeed.unique("eudi-verify");
        login = wallet.storedProvider(realm, loginAlias, Map.of());
        final WalletIdentityProvider verify = wallet.storedProvider(realm, verifyAlias, Map.of(
                "subject.strategy", "NONE",
                "verify.linkedProvider", loginAlias,
                "pid.requestedClaims", "[\"birthdate\",\"nationalities\"]",
                "verify.releasedClaims", "[\"age_over_18\",\"nationalities\"]",
                "dcApi.enabled", "true"));
        wallet.install(realm, login, verify);

        links = context.getBean(WalletLinkService.class);
        ada = seed().user(realm, E2eSeed.unique("ada"), PASSWORD);
        final E2eSeed.SeededUser bob = seed().user(realm, E2eSeed.unique("bob"), PASSWORD);
        adaNumber = "PAN-" + UUID.randomUUID();
        bobNumber = "PAN-" + UUID.randomUUID();
        assertThat(links.link(realm, ada.userId(), loginAlias, numberSubject(adaNumber)))
                .isEqualTo(WalletLinkService.LinkResult.LINKED);
        assertThat(links.link(realm, bob.userId(), loginAlias, numberSubject(bobNumber)))
                .isEqualTo(WalletLinkService.LinkResult.LINKED);

        final FlowAdminPublisher flows = context.getBean(FlowAdminPublisher.class);
        flows.create(new FlowCreateDto(realm, STEP_UP_FLOW, null));
        flows.save(new FlowSaveDto(realm, STEP_UP_FLOW, List.of(new FlowExecutionDto("wallet-verify", null,
                "eudi-wallet-verify", "REQUIRED", false, 10, Map.of("providerAlias", verifyAlias)))));
        bank = boundClient("bank");
        assertThat(context.getBean(io.helixiam.authorization.amqp.AuthFlowPublisher.class).retrieveFlowForClient(
                io.helixiam.authorization.support.RealmScopedKey.pack(realm, "bank")).getAlias())
                .as("the bank runs the step-up flow").isEqualTo(STEP_UP_FLOW);
    }

    // ------------------------------------------------------------------------------------------------ tests

    @Test
    void theUsersOwnWallet_stepsUpToHigh_throughTheDcApi_releasingOnlyTheConfiguredClaims() {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final Login login = signInThenWalletPage(newBrowser(), pkce, "bank");
        final Page page = login.dcApi();
        assertThat(page.protocol()).isEqualTo("openid4vp-v1-signed");

        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        final E2eHttp.Response posted = post(login, page.responseUrl(), body(request,
                sdJwtVpToken(request, pid(adaNumber))));
        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        assertThat(posted.json().path("status").asText()).isEqualTo("COMPLETED");
        final String next = posted.json().path("next").asText();
        assertThat(next).as(posted.toString()).contains("/flow/wallet/callback?response_code=");

        final E2eHttp.Response signedIn = login.browser().followRedirectsUntil(login.browser().get(next),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(signedIn.locationStartsWith(E2eSeed.REDIRECT_URI))
                .as(signedIn + "\n" + login.browser().trail(10)).isTrue();

        final OidcFlow oidc = new OidcFlow(login.browser(), realm);
        final JWTClaimsSet id = oidc.verify(oidc.exchangeCode("bank", bank.secret(), E2eSeed.REDIRECT_URI,
                OidcFlow.query(signedIn.location()).get("code"), pkce.verifier()).idToken());
        assertThat(id.getSubject()).isEqualTo(ada.userId());
        assertThat(id.getClaim("acr")).isEqualTo(HIGH);
        assertThat(id.getClaim("verified_claims")).isInstanceOf(Map.class);
        @SuppressWarnings("unchecked")
        final Map<String, Object> verified = (Map<String, Object>) id.getClaim("verified_claims");
        assertThat(verified.get("claims")).as("only the released claims, never the birth date or names")
                .isEqualTo(Map.of("age_over_18", true, "nationalities", "DE,NL"));
        assertThat(id.getClaims()).doesNotContainKeys("given_name", "family_name", "birthdate", "nationalities");

        final List<AuditRecord> success = awaitAudits(login.txId(), "WALLET_VERIFY_SUCCESS");
        assertThat(success).hasSize(1);
        assertThat(success.get(0).actor()).isEqualTo(ada.userId());
    }

    @Test
    void anotherPersonsWallet_overTheDcApi_isRefused() {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final Login login = signInThenWalletPage(newBrowser(), pkce, "bank");
        final Page page = login.dcApi();

        final DcApiWalletClient.DcApiRequest request = fetchRequest(login, page, origin());
        final E2eHttp.Response posted = post(login, page.responseUrl(), body(request,
                sdJwtVpToken(request, pid(bobNumber))));
        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        final String next = posted.json().path("next").asText();
        assertThat(next).as(posted.toString()).contains("/flow/wallet/callback?response_code=");

        final E2eHttp.Response refused = login.browser().followRedirectsUntil(login.browser().get(next),
                r -> r.locationStartsWith(E2eSeed.REDIRECT_URI));
        assertThat(refused.locationStartsWith(E2eSeed.REDIRECT_URI))
                .as("no code for someone else's wallet, over the DC API").isFalse();
        assertThat(refused.body()).as(refused + "\n" + login.browser().trail(8))
                .contains("id=\"walletVerifyError\"").contains("id=\"walletVerifyNotLinked\"");

        final List<AuditRecord> failure = awaitAudits(login.txId(), "WALLET_VERIFY_FAILURE");
        assertThat(failure).hasSize(1);
        assertThat(failure.get(0).actor()).isEqualTo(ada.userId());
        assertThat(failure.get(0).detail()).contains("\"reason\":\"BINDING_MISMATCH\"");
    }

    // ------------------------------------------------------------------------------------------------ helpers

    /** The page's origin as the browser serialises it: what the platform hands the wallet. */
    private static String origin() {
        final URI base = URI.create(baseUrl());
        return base.getScheme() + "://" + base.getHost() + (base.getPort() == -1 ? "" : ":" + base.getPort());
    }

    /** A confidential client bound to the step-up flow, asking for openid and verified_claims. */
    private E2eSeed.SeededClient boundClient(final String clientId) {
        final io.helixiam.authorization.amqp.client.ClientDto saved = context.getBean(
                io.helixiam.authorization.amqp.client.ClientAdminPublisher.class).create(
                new io.helixiam.authorization.amqp.client.ClientWriteDto(realm, null, clientId,
                        List.of("authorization_code", "refresh_token"), List.of(E2eSeed.REDIRECT_URI),
                        List.of("openid", "verified_claims"), null, STEP_UP_FLOW, clientId, "e2e step-up DC API client",
                        List.of(), List.of(), false, false, true, null, null, null, null, false, null, null, null,
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

    private static MatchedPresentations matched(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(new VerifiedPresentation("dc+sd-jwt", "urn:eudi:pid:1",
                Map.copyOf(claims), "CN=issuer", "01", "VALID")), java.util.Set.of());
    }

    /**
     * Starts {@code clientId}'s login, signs ada in with the first factor (a federated sign-in at eIDAS substantial,
     * the e2e broker stub), and follows to the wallet page the verification step sends the browser to.
     */
    private Login signInThenWalletPage(final E2eHttp browser, final OidcFlow.Pkce pkce, final String clientId) {
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=" + clientId
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=" + encode("openid verified_claims")
                + "&state=st&code_challenge=" + pkce.challenge() + "&code_challenge_method=S256";
        final E2eHttp.Response loginPage = browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        assertThat(loginPage.uri().getPath()).as(loginPage + "\n" + browser.trail(8)).endsWith("/login");
        final E2eHttp.Response page = browser.followRedirects(browser.get("/realms/" + realm
                + "/broker/e2e-stub/complete?userId=" + ada.userId() + "&loa=" + encode(SUBSTANTIAL)));
        assertThat(page.uri().getPath()).as(page + "\n" + browser.trail(10))
                .isEqualTo("/realms/" + realm + "/broker/" + verifyAlias + "/wallet");
        final URI location = page.uri();
        return new Login(browser, location.getPath() + "?" + location.getRawQuery(), page.body());
    }

    private static String encode(final String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }

    private record Page(String requestUrl, String responseUrl, String protocol, String csrfHeader, String csrfToken) {
    }

    private record Login(E2eHttp browser, String pageLocation, String page) {

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
        final TestWallet.SdJwtCredential presented = wallet.wallet().sdJwtPid(claims, now.minusSeconds(3600),
                now.plusSeconds(3600), Optional.empty());
        return Map.of("pid_sd_jwt", List.of(wallet.wallet().present(presented, claims.keySet(), request.audience(),
                request.nonce())));
    }

    private List<AuditRecord> audits(final String transactionId, final String type) {
        return context.getBean(AuditLogService.class).search(new AuditQuery(realm, type, null, null, null, 0, 100))
                .items().stream()
                .filter(r -> r.detail() != null && r.detail().contains("\"transactionId\":\"" + transactionId + "\""))
                .toList();
    }

    private List<AuditRecord> awaitAudits(final String transactionId, final String type) {
        final Instant deadline = Instant.now().plusSeconds(5);
        List<AuditRecord> seen = audits(transactionId, type);
        while (seen.size() < 1 && Instant.now().isBefore(deadline)) {
            sleep(25);
            seen = audits(transactionId, type);
        }
        sleep(300);
        return audits(transactionId, type);
    }

    private static void sleep(final long millis) {
        try {
            Thread.sleep(millis);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
