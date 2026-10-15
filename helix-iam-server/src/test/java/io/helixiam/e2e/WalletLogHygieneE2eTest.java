/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import tools.jackson.databind.JsonNode;
import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.authorization.federation.wallet.VerifiedPresentation;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletSubject;
import io.helixiam.authorization.federation.wallet.WalletSubjectResolver;
import io.helixiam.authorization.federation.wallet.dcql.MatchedPresentations;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Task 22 fix round 1 (Important #4-6): "no PID value, token, nonce or key appears in logs at any level" — proved
 * against the REAL booted server (full HTTP stack, real filter chain, real log4j2-spring.xml configuration), not a
 * bare unit test calling {@code WalletResponseHandler}/{@code WalletIdentityProvider} directly (the earlier version
 * of this test never exercised {@link io.helixiam.authorization.federation.wallet.WalletLoginCompleter} at all,
 * which is exactly where the subject hash leaked from in {@code WalletLinkService} — see the Task 22 review).
 *
 * <p>Covers both credential formats, both invocation flows, a JIT-provisioned login, an upgrade-link login (where
 * {@code commitPendingLink} actually runs), the account-console LINK flow, and one failure — all under
 * {@link LogCapture#all()} (every logger, the real root included, at the real app's configured levels since this is
 * a fully booted {@code @SpringBootTest}).
 */
class WalletLogHygieneE2eTest extends AbstractE2eTest {

    private WalletE2eFixture wallet;
    private String realm;
    private E2eSeed.SeededClient web;
    private String aliasSdJwt;
    private String aliasMdoc;
    private WalletIdentityProvider providerSdJwt;
    private WalletIdentityProvider providerMdoc;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("hygiene");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        aliasSdJwt = E2eSeed.unique("eudi-sdjwt");
        aliasMdoc = E2eSeed.unique("eudi-mdoc");
        // acknowledgeWeakSubject=true: needed for the tuple-based upgrade-link and account-console LINK scenarios.
        providerSdJwt = wallet.storedProvider(realm, aliasSdJwt, Map.of("subject.acknowledgeWeakSubject", "true"));
        providerMdoc = wallet.storedProviderMdoc(realm, aliasMdoc, Map.of("subject.acknowledgeWeakSubject", "true"));
        wallet.install(realm, providerSdJwt, providerMdoc);
    }

    // ------------------------------------------------------------------------------------------------ JIT (sd-jwt)

    @Test
    void sdJwt_crossDevice_jitProvisioning_leaksNothing() throws Exception {
        final Map<String, Object> pid = pid("Hygiene-Jit-Erika", "Hygiene-Jit-Mustermann", "PAN-" + UUID.randomUUID());
        try (LogCapture logs = LogCapture.all()) {
            final Login login = startLogin(newBrowser(), aliasSdJwt);
            final WalletTransaction tx = transactionOf(login);
            final E2eHttp phone = newBrowser();
            final Oid4vpWalletClient.VerifiedRequest request =
                    WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
            final Map<String, Object> vpToken = wallet.vpToken(request, pid);
            final Secrets secrets = secretsOf(pid, request, tx, vpToken, providerSdJwt, null);

            assertThat(wallet.respondWith(phone, request, vpToken).status()).isEqualTo(200);
            final String next = poll(login).path("next").asText();
            final String code = codeOf(next);
            assertThat(finishSignIn(login, next)).isNotBlank();

            secrets.withResponseCode(code).assertAbsentFrom(logs.text());
        }
    }

    // ------------------------------------------------------------------------------------------------ JIT (mdoc)

    @Test
    void mdoc_sameDevice_jitProvisioning_leaksNothing() throws Exception {
        final Map<String, Object> pid = mdocPid("Hygiene-Mdoc-Erika", "Hygiene-Mdoc-Mustermann",
                "PAN-" + UUID.randomUUID());
        try (LogCapture logs = LogCapture.all()) {
            final Login login = startLogin(newBrowser(), aliasMdoc);
            final WalletTransaction tx = transactionOf(login);
            final Oid4vpWalletClient.VerifiedRequest request =
                    WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));
            final Map<String, Object> vpToken = wallet.mdocVpToken(request, pid);
            final Secrets secrets = secretsOf(pid, request, tx, vpToken, providerMdoc, null);

            final E2eHttp.Response posted = wallet.respondWith(login.browser(), request, vpToken);
            assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
            final String redirectUri = posted.json().path("redirect_uri").asText();
            final String code = codeOf(redirectUri);
            assertThat(finishSignIn(login, redirectUri)).isNotBlank();

            secrets.withResponseCode(code).assertAbsentFrom(logs.text());
        }
    }

    // ------------------------------------------------------------------------------------------------ upgrade link

    /**
     * A tuple is already linked to an account; this login's number matches the same tuple and is unlinked, so the
     * login resolves via the tuple (the upgrade path) and, once it succeeds, commits the number too
     * ({@code WalletLinkService.commitPendingLink} — exactly where the subject hash used to leak, see the review).
     */
    @Test
    void sdJwt_sameDevice_upgradeLink_commitsThePendingNumberLink_leaksNothing() throws Exception {
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada"), "Wallet-Hygiene-Passw0rd-2026!");
        final Map<String, Object> tuplePid = pid("Hygiene-Upgrade-Erika", "Hygiene-Upgrade-Mustermann", null);
        final WalletLinkService links = context.getBean(WalletLinkService.class);
        final WalletSubjectResolver resolver = context.getBean(WalletSubjectResolver.class);
        final WalletSubject tuple = resolver.resolve(realm, matched(tuplePid), providerSdJwt.config());
        assertThat(links.link(realm, ada.userId(), aliasSdJwt, tuple)).isEqualTo(WalletLinkService.LinkResult.LINKED);
        final String number = "PAN-" + UUID.randomUUID();
        final Map<String, Object> numberPid = new LinkedHashMap<>(tuplePid);
        numberPid.put("personal_administrative_number", number);
        final WalletSubject.AdminNumber numberSubject = (WalletSubject.AdminNumber) resolver.resolve(realm,
                matched(numberPid), providerSdJwt.config());
        assertThat(links.find(realm, aliasSdJwt, new WalletSubject.AdminNumber(numberSubject.value(), null)))
                .as("not linked yet").isEmpty();

        try (LogCapture logs = LogCapture.all()) {
            final Login login = startLogin(newBrowser(), aliasSdJwt);
            final WalletTransaction tx = transactionOf(login);
            final Oid4vpWalletClient.VerifiedRequest request =
                    WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));
            final Map<String, Object> vpToken = wallet.vpToken(request, numberPid);
            final Secrets secrets = secretsOf(numberPid, request, tx, vpToken, providerSdJwt,
                    List.of(((WalletSubject.Tuple) tuple).value(), numberSubject.value()));

            final E2eHttp.Response posted = wallet.respondWith(login.browser(), request, vpToken);
            assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
            final String redirectUri = posted.json().path("redirect_uri").asText();
            final String code = codeOf(redirectUri);
            assertThat(finishSignIn(login, redirectUri)).isEqualTo(ada.userId());
            // the whole point of this scenario: the number got committed via commitPendingLink
            assertThat(links.find(realm, aliasSdJwt, new WalletSubject.AdminNumber(numberSubject.value(), null)))
                    .contains(ada.userId());

            secrets.withResponseCode(code).assertAbsentFrom(logs.text());
        }
    }

    // ------------------------------------------------------------------------------------------------ account console

    @Test
    void accountConsoleLinkFlow_leaksNothing() throws Exception {
        final String password = "Wallet-Hygiene-Link-Passw0rd-2026!";
        final E2eSeed.SeededUser ada = seed().user(realm, E2eSeed.unique("ada-link"), password);
        final Map<String, Object> pid = pid("Hygiene-Link-Erika", "Hygiene-Link-Mustermann", null);
        final WalletSubjectResolver resolver = context.getBean(WalletSubjectResolver.class);
        final WalletSubject tuple = resolver.resolve(realm, matched(pid), providerSdJwt.config());

        try (LogCapture logs = LogCapture.all()) {
            final E2eHttp console = E2eAdminSession.login(newBrowser(), realm, ada.username(), password).http();
            final String account = "/realms/" + realm + "/account";
            final String csrf = E2eHttp.csrf(console.get(account).body());
            final E2eHttp.Response start = console.postForm(account + "/wallet/link",
                    Map.of("_csrf", csrf, "alias", aliasSdJwt));
            assertThat(start.status()).as(start.toString()).isEqualTo(302);
            final URI location = start.location();
            final String pageLocation = location.getPath() + "?" + location.getRawQuery();
            final E2eHttp.Response page = console.get(pageLocation);
            assertThat(page.status()).as(page.toString()).isEqualTo(200);
            final WalletTransaction tx = context.getBean(WalletTransactionStore.class)
                    .byTransactionId(WalletE2eFixture.txId(pageLocation)).orElseThrow();

            final E2eHttp phone = newBrowser();
            final Oid4vpWalletClient.VerifiedRequest request =
                    WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(page.body()));
            final Map<String, Object> vpToken = wallet.vpToken(request, pid);
            final Secrets secrets = secretsOf(pid, request, tx, vpToken, providerSdJwt,
                    List.of(((WalletSubject.Tuple) tuple).value()));
            assertThat(wallet.respondWith(phone, request, vpToken).status()).isEqualTo(200);

            final String status = pageLocation.substring(0, pageLocation.indexOf('?')) + "/status?"
                    + location.getRawQuery();
            final JsonNode polled = console.get(status, "Accept", "application/json").json();
            assertThat(polled.path("status").asText()).isEqualTo("COMPLETED");
            final String next = polled.path("next").asText();
            final String code = codeOf(next);
            final E2eHttp.Response callback = console.followRedirects(console.get(next));
            assertThat(callback.body()).contains("Your wallet is linked.");
            assertThat(context.getBean(WalletLinkService.class).find(realm, aliasSdJwt, tuple))
                    .contains(ada.userId());

            secrets.withResponseCode(code).assertAbsentFrom(logs.text());
        }
    }

    // ------------------------------------------------------------------------------------------------ failure

    @Test
    void failurePath_leaksNothing() {
        try (LogCapture logs = LogCapture.all()) {
            final Login login = startLogin(newBrowser(), aliasSdJwt);
            final WalletTransaction tx = transactionOf(login);
            final E2eHttp phone = newBrowser();
            final Oid4vpWalletClient.VerifiedRequest request =
                    WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

            final E2eHttp.Response posted = phone.postForm(request.responseUri(),
                    Map.of("error", "access_denied", "state", request.state()));

            assertThat(posted.status()).isEqualTo(200);
            assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
            assertThat(logs.text()).as("nonce").doesNotContain(request.nonce()).as("binding")
                    .doesNotContain(tx.browserBindingHash());
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private record Login(E2eHttp browser, OidcFlow.Pkce pkce, String pageLocation, String page) {
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

    private WalletTransaction transactionOf(final Login login) {
        return context.getBean(WalletTransactionStore.class)
                .byTransactionId(WalletE2eFixture.txId(login.pageLocation())).orElseThrow();
    }

    private String statusPath(final Login login) {
        final String tx = WalletE2eFixture.txId(login.pageLocation());
        return login.pageLocation().substring(0, login.pageLocation().indexOf('?')) + "/status?tx=" + tx;
    }

    private JsonNode poll(final Login login) {
        final E2eHttp.Response status = login.browser().get(statusPath(login), "Accept", "application/json");
        assertThat(status.status()).as(status.toString()).isEqualTo(200);
        return status.json();
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
        return oidc.verify(tokens.idToken()).getSubject();
    }

    /** The {@code response_code} query parameter of a same-device {@code redirect_uri} or a polled {@code next}. */
    private static String codeOf(final String url) {
        final String marker = "response_code=";
        final int i = url.indexOf(marker);
        assertThat(i).as("response_code in " + url).isNotNegative();
        return url.substring(i + marker.length());
    }

    private static Map<String, Object> pid(final String givenName, final String familyName, final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", givenName);
        claims.put("family_name", familyName);
        claims.put("birthdate", "1984-01-26");
        claims.put("issuing_country", "DE");
        if (number != null) {
            claims.put("personal_administrative_number", number);
        }
        return claims;
    }

    /**
     * mdoc element identifiers, not SD-JWT claim names — {@code DcqlQueryBuilder.PID_CLAIMS} maps SD-JWT's
     * {@code birthdate} to mdoc's {@code birth_date}; using the SD-JWT name here would leave the mdoc PID without the
     * element the default DCQL query asks for ({@code DCQL_NOT_SATISFIED}, not a hygiene failure).
     */
    private static Map<String, Object> mdocPid(final String givenName, final String familyName,
                                                final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", givenName);
        claims.put("family_name", familyName);
        claims.put("birth_date", "1984-01-26");
        claims.put("issuing_country", "DE");
        if (number != null) {
            claims.put("personal_administrative_number", number);
        }
        return claims;
    }

    private static MatchedPresentations matched(final Map<String, Object> claims) {
        return new MatchedPresentations(List.of(new VerifiedPresentation("dc+sd-jwt", "urn:eudi:pid:1",
                Map.copyOf(claims), "CN=issuer", "01", "VALID")), Set.of());
    }

    /** Everything a login must never leak into the logs, collected before the response is submitted. */
    private record Secrets(List<String> pidValues, String nonce, List<String> vpTokenFragments, String ephemeralJwkD,
            String binding, List<String> subjectHashes, String responseCode) {

        Secrets withResponseCode(final String code) {
            return new Secrets(pidValues, nonce, vpTokenFragments, ephemeralJwkD, binding, subjectHashes, code);
        }

        void assertAbsentFrom(final String text) {
            for (final String pid : pidValues) {
                assertThat(text).as("PID value '%s'", pid).doesNotContain(pid);
            }
            assertThat(text).as("nonce").doesNotContain(nonce);
            for (final String fragment : vpTokenFragments) {
                assertThat(text).as("vp_token fragment '%s'", fragment).doesNotContain(fragment);
            }
            if (ephemeralJwkD != null) {
                assertThat(text).as("ephemeral response-key d").doesNotContain(ephemeralJwkD);
            }
            assertThat(text).as("binding").doesNotContain(binding);
            for (final String hash : subjectHashes) {
                assertThat(text).as("subject hash '%s'", hash).doesNotContain(hash);
            }
            if (responseCode != null) {
                assertThat(text).as("response_code").doesNotContain(responseCode);
            }
        }
    }

    /** The first 20 characters of {@code value} (or all of it, if shorter) — a safe, distinctive fragment to assert. */
    private static String firstChars(final String value) {
        return value.substring(0, Math.min(20, value.length()));
    }

    /**
     * Collects every secret a login of {@code pid} will carry: the distinctive PID values (name/number, "DE" and the
     * fixed birthdate are too short to assert without false positives), the transaction's nonce/binding/ephemeral key,
     * a fragment of the exact submitted {@code vp_token} (the first 20 characters of its SD-JWT issuer-JWT part, or of
     * the base64url mdoc DeviceResponse), and the given subject hash(es) (the login's own, plus any extra ones a
     * caller already resolved, e.g. a pre-existing tuple link).
     */
    private Secrets secretsOf(final Map<String, Object> pid, final Oid4vpWalletClient.VerifiedRequest request,
                              final WalletTransaction tx, final Map<String, Object> vpToken,
                              final WalletIdentityProvider provider, final List<String> extraSubjectHashes)
            throws ParseException {
        final List<String> pidValues = pid.values().stream().map(Object::toString)
                .filter(v -> v.length() > 4).toList(); // "DE" and similarly short values are excluded deliberately
        final String ephemeralD = tx.encryptionJwkJson() == null ? null : ECKey.parse(tx.encryptionJwkJson()).getD()
                .toString();
        final Object raw = vpToken.values().iterator().next();
        final String presentation = ((List<?>) raw).get(0).toString();
        final List<String> fragments = new java.util.ArrayList<>();
        if (presentation.contains("~")) {
            // SD-JWT: <issuer-JWT>~<disclosure>~...~<kb-JWT> — the issuer JWT and (when present) a disclosure.
            final String[] parts = presentation.split("~");
            fragments.add(firstChars(parts[0]));
            if (parts.length > 1 && !parts[1].isEmpty()) {
                fragments.add(firstChars(parts[1]));
            }
        } else {
            // mdoc: the whole string is the base64url-encoded DeviceResponse.
            fragments.add(firstChars(presentation));
        }
        final WalletSubjectResolver resolver = context.getBean(WalletSubjectResolver.class);
        final WalletSubject subject = resolver.resolve(realm, matched(pid), provider.config());
        final List<String> hashes = new java.util.ArrayList<>();
        switch (subject) {
            case WalletSubject.AdminNumber n -> hashes.add(n.value());
            case WalletSubject.Tuple t -> hashes.add(t.value());
            case WalletSubject.Unavailable u -> { /* nothing resolvable */ }
        }
        if (extraSubjectHashes != null) {
            hashes.addAll(extraSubjectHashes);
        }
        return new Secrets(pidValues, request.nonce(), fragments, ephemeralD, tx.browserBindingHash(), hashes, null);
    }
}
