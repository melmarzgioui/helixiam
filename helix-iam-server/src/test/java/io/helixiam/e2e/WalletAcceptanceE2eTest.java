/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e;

import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JOSEException;
import io.helixiam.authorization.domain.audit.AuditQuery;
import io.helixiam.authorization.domain.audit.AuditRecord;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletFakeVerifiers;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.MdocCredential;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet.SdJwtCredential;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.service.audit.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * Task 23: the spec &sect;15 acceptance matrix, end to end over real HTTP (the {@link WalletFlowE2eTest} style: a
 * real {@link E2eHttp} browser, {@link WalletE2eFixture}, {@code TestWallet}), both credential formats wherever a
 * row applies to both.
 *
 * <h2>What is pinned here</h2>
 * <ul>
 *   <li>Row 1 (configuration + icon): {@link #configuredProviders_appearOnTheLoginPage_withTheWalletIcon()}.</li>
 *   <li>Rows 2-4 (cross/same-device, mapped claims, {@code acr}, either format satisfies the default DCQL
 *       {@code credential_sets}): {@link #crossDevice_sdJwtPid_signsIn_withMappedClaimsAndLoaHigh()} and
 *       {@link #sameDevice_mdocPid_signsIn_onTheSameDualFormatProvider()}, on ONE provider configured for both
 *       formats.</li>
 *   <li>Row 5 (every rejection, its own {@link WalletErrorCode} + a {@code WALLET_LOGIN_FAILURE} audit): the content
 *       checks ({@link #sdJwtContentRejection_mapsToItsOwnCode_andAudits}, {@link
 *       #mdocContentRejection_mapsToItsOwnCode_andAudits}) drive a genuinely malformed presentation through the REAL
 *       verifier for both formats — {@link WalletAuditE2eTest} already did this at the handler level for
 *       {@code dc+sd-jwt} only; revoked, replay, reused code, cross-browser redemption, transaction expiry and
 *       wallet {@code access_denied} are format-agnostic protocol checks, each pinned once over real HTTP with its
 *       audit reason. {@code CREDENTIAL_REVOKED} reuses {@link WalletAuditE2eTest}'s "real pipeline, fake content
 *       check" substitution ({@link WalletFakeVerifiers}) because this shared e2e context has no reachable
 *       status-list host; every other code is a genuine bad presentation.</li>
 *   <li>Unrequested-claim over-disclosure: dropped, not rejected ({@link #unrequestedClaim_sdJwt_isDropped_notRejected()},
 *       {@link #unrequestedClaim_mdoc_isDropped_notRejected()}) — the login still succeeds and the undropped claims
 *       (not the extra one) reach {@code /userinfo}.</li>
 * </ul>
 *
 * <h2>What is NOT repeated here (already pinned elsewhere, &sect;15)</h2>
 * <ul>
 *   <li>{@code direct_post} refused under the production-readiness check: {@code ProductionReadinessCheckTest}.</li>
 *   <li>No PID value/token/nonce/key in logs: {@code WalletLogHygieneE2eTest} (both formats, a real booted server,
 *       the full log output captured).</li>
 *   <li>Redis store: concurrent duplicate {@code direct_post} gives exactly one success: {@code
 *       AbstractWalletTransactionStoreTest#claimResponse_from20ThreadsAtOnce_exactlyOneWins} (run against both the
 *       in-memory and the real Redis store).</li>
 *   <li>The full existing suite passing, CodeQL triage, docs: verified/updated by the Task 23 report, not a test.</li>
 * </ul>
 */
class WalletAcceptanceE2eTest extends AbstractE2eTest {

    private static final String AUD_ATTACKER = "x509_san_dns:attacker.example";

    private WalletE2eFixture wallet;
    private String realm;
    private String alias;
    private E2eSeed.SeededClient web;
    private WalletIdentityProvider providerBoth;

    @BeforeEach
    void setUp() {
        wallet = new WalletE2eFixture(context);
        realm = E2eSeed.unique("accept");
        seed().realm(realm);
        web = seed().confidentialClient(realm, "web", List.of("openid", "profile"));
        alias = E2eSeed.unique("eudi");
        providerBoth = wallet.storedProviderBothFormats(realm, alias, Map.of());
        wallet.install(realm, providerBoth);
    }

    // ============================================================================================ row 1 — config

    @Test
    void configuredProviders_appearOnTheLoginPage_withTheWalletIcon() {
        final String storedAlias = E2eSeed.unique("eudi-stored");
        final String yamlAlias = E2eSeed.unique("eudi-yaml");
        wallet.install(realm, wallet.storedProvider(realm, storedAlias, Map.of()), wallet.yamlProvider(yamlAlias));

        final E2eHttp.Response page = newBrowser().get("/realms/" + realm + "/login", "Accept", "text/html");

        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        assertThat(page.body()).contains("/broker/" + storedAlias).contains("/broker/" + yamlAlias);
        assertThat(countOccurrences(page.body(), "idp-eudi-wallet"))
                .as("both the stored and the YAML provider show the wallet mark").isEqualTo(2);
        // content-hashed + realm-prefixed static path (e.g. .../img/idp/eudi-wallet-<hash>.svg): match by pattern.
        assertThat(countOccurrences(page.body(), "img/idp/eudi-wallet-")).isEqualTo(2);
        assertThat(page.body()).containsPattern("img/idp/eudi-wallet-[0-9a-f]+\\.svg");
    }

    private static int countOccurrences(final String haystack, final String needle) {
        int count = 0;
        int from = 0;
        while ((from = haystack.indexOf(needle, from)) >= 0) {
            count++;
            from += needle.length();
        }
        return count;
    }

    // ============================================================================================ rows 2-4 — happy

    @Test
    void crossDevice_sdJwtPid_signsIn_withMappedClaimsAndLoaHigh() throws Exception {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        final Map<String, Object> claims = sdJwtClaims("PAN-" + UUID.randomUUID());

        final E2eHttp.Response posted = wallet.respond(phone, request, claims);
        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);

        final String next = poll(login).path("next").asText();
        final Finished finished = finishSignIn(login, next);
        assertThat(finished.acr()).isEqualTo("http://eidas.europa.eu/LoA/high");

        final JsonNode userinfo = oidc().userinfo(finished.accessToken()).json();
        assertThat(userinfo.path("given_name").asText()).isEqualTo("Erika");
        assertThat(userinfo.path("family_name").asText()).isEqualTo("Mustermann");
    }

    @Test
    void sameDevice_mdocPid_signsIn_onTheSameDualFormatProvider() throws Exception {
        final Login login = startLogin(newBrowser());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));
        final Map<String, Object> claims = mdocClaims("PAN-" + UUID.randomUUID());

        final E2eHttp.Response posted = wallet.respondWith(login.browser(), request, wallet.mdocVpToken(request, claims));
        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        final String redirectUri = posted.json().path("redirect_uri").asText();

        final Finished finished = finishSignIn(login, redirectUri);
        assertThat(finished.acr()).isEqualTo("http://eidas.europa.eu/LoA/high");

        final JsonNode userinfo = oidc().userinfo(finished.accessToken()).json();
        assertThat(userinfo.path("given_name").asText()).isEqualTo("Erika");
        assertThat(userinfo.path("family_name").asText()).isEqualTo("Mustermann");
    }

    // ============================================================================================ row 5 — sd-jwt

    @ParameterizedTest
    @EnumSource(value = WalletErrorCode.class, names = {"ISSUER_SIGNATURE_INVALID", "ISSUER_UNTRUSTED",
            "CREDENTIAL_EXPIRED", "NONCE_MISMATCH", "AUDIENCE_MISMATCH", "HOLDER_BINDING_MISSING"})
    void sdJwtContentRejection_mapsToItsOwnCode_andAudits(final WalletErrorCode code) {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

        final String presentation = sdJwtBadPresentation(code, request);

        final E2eHttp.Response posted = wallet.respondWith(phone, request,
                Map.of("pid_sd_jwt", List.of(presentation)));

        assertRejected(posted);
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
        assertAudited(code);
    }

    private String sdJwtBadPresentation(final WalletErrorCode code, final Oid4vpWalletClient.VerifiedRequest request) {
        final TestWallet good = wallet.wallet();
        final Map<String, Object> claims = sdJwtClaims("PAN-" + UUID.randomUUID());
        return switch (code) {
            case ISSUER_SIGNATURE_INVALID -> {
                final SdJwtCredential cred = good.sdJwtPid(claims, Instant.now().minusSeconds(60),
                        Instant.now().plusSeconds(3600), Optional.empty());
                final String tampered = withIssuerPayload(cred.issuerJwt(),
                        payloadJson(cred.issuerJwt()).replace("\"" + TestWallet.ISSUER + "\"", "\"https://evil.example\""));
                yield good.present(cred.withIssuerJwt(tampered), claims.keySet(), request.clientId(), request.nonce());
            }
            case ISSUER_UNTRUSTED -> {
                final TestWallet other = TestWallet.create();
                final SdJwtCredential cred = other.sdJwtPid(claims, Instant.now().minusSeconds(60),
                        Instant.now().plusSeconds(3600), Optional.empty());
                yield other.present(cred, claims.keySet(), request.clientId(), request.nonce());
            }
            case CREDENTIAL_EXPIRED -> {
                final Instant now = Instant.now();
                final SdJwtCredential cred = good.sdJwtPid(claims, now.minusSeconds(7200), now.minusSeconds(61),
                        Optional.empty());
                yield good.present(cred, claims.keySet(), request.clientId(), request.nonce());
            }
            case NONCE_MISMATCH -> {
                final SdJwtCredential cred = good.sdJwtPid(claims, Instant.now().minusSeconds(60),
                        Instant.now().plusSeconds(3600), Optional.empty());
                yield good.present(cred, claims.keySet(), request.clientId(), "wrong-nonce");
            }
            case AUDIENCE_MISMATCH -> {
                final SdJwtCredential cred = good.sdJwtPid(claims, Instant.now().minusSeconds(60),
                        Instant.now().plusSeconds(3600), Optional.empty());
                yield good.present(cred, claims.keySet(), AUD_ATTACKER, request.nonce());
            }
            case HOLDER_BINDING_MISSING -> {
                final SdJwtCredential cred = good.sdJwtPid(claims, Instant.now().minusSeconds(60),
                        Instant.now().plusSeconds(3600), Optional.empty());
                yield good.presentWithoutKeyBinding(cred, claims.keySet());
            }
            default -> throw new IllegalArgumentException(code.name());
        };
    }

    private static String payloadJson(final String jwt) {
        return new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    /** Replaces the issuer payload but keeps header and signature: an attacker's edit. */
    private static String withIssuerPayload(final String issuerJwt, final String payloadJson) {
        final String[] parts = issuerJwt.split("\\.");
        return parts[0] + "." + TestWallet.b64url(payloadJson) + "." + parts[2];
    }

    // ============================================================================================ row 5 — mdoc

    /**
     * Mdoc analogue of {@link #sdJwtContentRejection_mapsToItsOwnCode_andAudits}: WRONG_NONCE and WRONG_AUD are kept
     * distinct scenarios (matching &sect;15's "wrong nonce" / "wrong aud" rows) even though the mdoc SessionTranscript
     * hash conflates both into {@code HOLDER_BINDING_INVALID} — see {@code MdocPresentationVerifierTest}'s
     * {@code transcriptWithAnotherNonceIsHolderBindingInvalidNotNonceMismatch}; this is documented verifier behaviour,
     * not a gap, so no production code change follows from it.
     */
    private enum MdocRejection { SIGNATURE, UNTRUSTED, EXPIRED, WRONG_NONCE, WRONG_AUD, MISSING_DEVICE_AUTH }

    @ParameterizedTest
    @EnumSource(MdocRejection.class)
    void mdocContentRejection_mapsToItsOwnCode_andAudits(final MdocRejection scenario) {
        final Login login = startLogin(newBrowser());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));

        final WalletErrorCode expected = switch (scenario) {
            case SIGNATURE -> WalletErrorCode.ISSUER_SIGNATURE_INVALID;
            case UNTRUSTED -> WalletErrorCode.ISSUER_UNTRUSTED;
            case EXPIRED -> WalletErrorCode.CREDENTIAL_EXPIRED;
            case WRONG_NONCE, WRONG_AUD, MISSING_DEVICE_AUTH -> scenario == MdocRejection.MISSING_DEVICE_AUTH
                    ? WalletErrorCode.HOLDER_BINDING_MISSING : WalletErrorCode.HOLDER_BINDING_INVALID;
        };
        final String vpToken = TestWallet.b64url(TestWallet.cbor(mdocBadResponse(scenario, request)));

        final E2eHttp.Response posted = wallet.respondWith(login.browser(), request,
                Map.of("pid_mdoc", List.of(vpToken)));

        assertRejected(posted);
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
        assertAudited(expected);
    }

    @SuppressWarnings("unchecked")
    private Map<Object, Object> mdocBadResponse(final MdocRejection scenario,
            final Oid4vpWalletClient.VerifiedRequest request) {
        final TestWallet good = wallet.wallet();
        final Map<String, Object> claims = mdocClaims("PAN-" + UUID.randomUUID());
        final Instant now = Instant.now();
        return switch (scenario) {
            case SIGNATURE -> {
                final MdocCredential cred = good.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.plusSeconds(3600), Optional.empty());
                final MdocCredential other = good.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.plusSeconds(3600), Optional.empty());
                final Map<Object, Object> response = TestWallet.mdocDeviceResponseStructure(cred, claims.keySet(),
                        WalletE2eFixture.mdocSessionTranscript(request));
                final Map<Object, Object> issuerSigned = issuerSigned(response);
                ((List<Object>) issuerSigned.get("issuerAuth")).set(2, other.mso());
                yield response;
            }
            case UNTRUSTED -> {
                final TestWallet other = TestWallet.create();
                final MdocCredential cred = other.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.plusSeconds(3600), Optional.empty());
                yield TestWallet.mdocDeviceResponseStructure(cred, claims.keySet(),
                        WalletE2eFixture.mdocSessionTranscript(request));
            }
            case EXPIRED -> {
                final MdocCredential cred = good.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.minusSeconds(120), Optional.empty());
                yield TestWallet.mdocDeviceResponseStructure(cred, claims.keySet(),
                        WalletE2eFixture.mdocSessionTranscript(request));
            }
            case WRONG_NONCE -> {
                final MdocCredential cred = good.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.plusSeconds(3600), Optional.empty());
                yield TestWallet.mdocDeviceResponseStructure(cred, claims.keySet(),
                        transcript(request.clientId(), "wrong-nonce", thumbprintOf(request), request.responseUri()));
            }
            case WRONG_AUD -> {
                final MdocCredential cred = good.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.plusSeconds(3600), Optional.empty());
                yield TestWallet.mdocDeviceResponseStructure(cred, claims.keySet(),
                        transcript(AUD_ATTACKER, request.nonce(), thumbprintOf(request), request.responseUri()));
            }
            case MISSING_DEVICE_AUTH -> {
                final MdocCredential cred = good.mdocPid(claims, now.minusSeconds(3600), now.minusSeconds(3600),
                        now.plusSeconds(3600), Optional.empty());
                final Map<Object, Object> response = TestWallet.mdocDeviceResponseStructure(cred, claims.keySet(),
                        WalletE2eFixture.mdocSessionTranscript(request));
                deviceSigned(response).remove("deviceAuth");
                yield response;
            }
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> document(final Map<Object, Object> response) {
        return (Map<Object, Object>) ((List<Object>) response.get("documents")).get(0);
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> issuerSigned(final Map<Object, Object> response) {
        return (Map<Object, Object>) document(response).get("issuerSigned");
    }

    @SuppressWarnings("unchecked")
    private static Map<Object, Object> deviceSigned(final Map<Object, Object> response) {
        return (Map<Object, Object>) document(response).get("deviceSigned");
    }

    /** The OpenID4VP redirect SessionTranscript (Annex B), written independently of production code. */
    private static byte[] transcript(final String clientId, final String nonce, final byte[] thumbprint,
            final String responseUri) {
        final byte[] info = TestWallet.cbor(Arrays.asList(clientId, nonce, thumbprint, responseUri));
        return TestWallet.cbor(Arrays.asList(null, null,
                List.of("OpenID4VPHandover", TestWallet.sha("SHA-256", info))));
    }

    private static byte[] thumbprintOf(final Oid4vpWalletClient.VerifiedRequest request) {
        if (request.encryptionKey() == null) {
            return null;
        }
        try {
            return request.encryptionKey().toPublicJWK().computeThumbprint("SHA-256").decode();
        } catch (final JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    // ============================================================================================ row 5 — revoked

    @Test
    void credentialRevoked_sdJwt_isRejected_andAudited() {
        final WalletIdentityProvider fake = WalletFakeVerifiers.withThrowingVerifier(providerBoth,
                WalletErrorCode.CREDENTIAL_REVOKED, context.getBean(AuditLog.class));
        wallet.install(realm, fake);
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

        final E2eHttp.Response posted = wallet.respond(phone, request, sdJwtClaims("PAN-" + UUID.randomUUID()));

        assertRejected(posted);
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
        assertAudited(WalletErrorCode.CREDENTIAL_REVOKED);
    }

    @Test
    void credentialRevoked_mdoc_isRejected_andAudited() {
        final WalletIdentityProvider fake = WalletFakeVerifiers.withThrowingVerifier(providerBoth,
                WalletErrorCode.CREDENTIAL_REVOKED, context.getBean(AuditLog.class));
        wallet.install(realm, fake);
        final Login login = startLogin(newBrowser());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));

        final E2eHttp.Response posted = wallet.respondWith(login.browser(), request,
                wallet.mdocVpToken(request, mdocClaims("PAN-" + UUID.randomUUID())));

        assertRejected(posted);
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
        assertAudited(WalletErrorCode.CREDENTIAL_REVOKED);
    }

    // ============================================================================================ row 5 — protocol

    @Test
    void replayedDirectPost_isRejected_andAuditedOnce() {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        final Map<String, Object> vpToken = wallet.vpToken(request, sdJwtClaims("PAN-" + UUID.randomUUID()));

        assertThat(wallet.respondWith(phone, request, vpToken).status()).isEqualTo(200);
        final E2eHttp.Response replay = wallet.respondWith(phone, request, vpToken);

        assertRejected(replay);
        assertThat(poll(login).path("status").asText()).as("the first response stands").isEqualTo("COMPLETED");
        assertAudited(WalletErrorCode.REPLAY);
    }

    /**
     * Over real HTTP, the FIRST layer any reuse of a broker callback hits is {@code FederationBrokerController}'s OWN
     * single-use anti-forgery state ("consumed from the session on callback" — its class javadoc): it is gone from
     * the session the moment the FIRST callback is handled, so a second hit in the SAME browser session gets
     * {@code STATE_MISMATCH} there, before ever reaching {@link WalletIdentityProvider#callback}'s own
     * {@code response_code} single-use check. {@code WalletAuditE2eTest.reusedResponseCode_isReplay_andAuditedOnce}
     * pins the wallet-level {@code REPLAY} check by calling {@code provider.callback(...)} directly, bypassing this
     * outer layer — which a real browser can never do. Both checks exist and both refuse the second redemption; this
     * test pins what a real browser actually gets.
     */
    @Test
    void reusedResponseCode_secondRedemptionIsRejected_andAudited() {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(wallet.respond(phone, request, sdJwtClaims("PAN-" + UUID.randomUUID())).status()).isEqualTo(200);
        final String next = poll(login).path("next").asText();
        assertThat(finishSignIn(login, next).subject()).isNotBlank();

        // The same (now-spent) response_code redeemed again in the same browser session.
        final E2eHttp.Response second = login.browser().get(next);

        assertThat(second.status()).isEqualTo(302);
        assertThat(second.location().toString()).endsWith("/login?error=federation");
        assertAudited(WalletErrorCode.STATE_MISMATCH);
    }

    /**
     * See {@link #reusedResponseCode_secondRedemptionIsRejected_andAudited}: a browser that never started THIS
     * transaction never carries the broker's single-use anti-forgery state for it either, so it is refused with
     * {@code STATE_MISMATCH} before {@link WalletIdentityProvider#callback}'s own browser-binding check
     * ({@code BROWSER_MISMATCH}, pinned directly in {@code WalletAuditE2eTest}) is ever reached.
     */
    @Test
    void redeemFromAnotherBrowserSession_isRejected_andAudited() {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        assertThat(wallet.respond(phone, request, sdJwtClaims("PAN-" + UUID.randomUUID())).status()).isEqualTo(200);
        final String next = poll(login).path("next").asText();
        final E2eHttp attacker = newBrowser();
        attacker.followRedirects(attacker.get("/realms/" + realm + "/login"));

        final E2eHttp.Response stolen = attacker.get(next);

        assertThat(stolen.status()).isEqualTo(302);
        assertThat(stolen.location().toString()).endsWith("/login?error=federation");
        assertAudited(WalletErrorCode.STATE_MISMATCH);
        // ...and the code is not burned for the browser it actually belongs to.
        assertThat(finishSignIn(login, next).subject()).isNotBlank();
    }

    @Test
    void expiredTransactionBetweenClaimAndComplete_isRejected_andAudited() {
        final WalletTransactionStore spyStore = spy(providerBoth.transactions());
        when(spyStore.complete(any(), any(), any())).thenReturn(false); // simulate expiry winning the race
        final WalletIdentityProvider fake = WalletFakeVerifiers.withTransactionStore(providerBoth, spyStore,
                context.getBean(AuditLog.class));
        wallet.install(realm, fake);
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

        final E2eHttp.Response posted = wallet.respond(phone, request, sdJwtClaims("PAN-" + UUID.randomUUID()));

        assertRejected(posted);
        assertAudited(WalletErrorCode.TRANSACTION_EXPIRED);
    }

    @Test
    void walletAccessDenied_isRejected_andAudited() {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));

        final E2eHttp.Response posted = phone.postForm(request.responseUri(),
                Map.of("error", "access_denied", "state", request.state()));

        assertThat(posted.status()).as("a processed error response is a 200 (OpenID4VP §8.2)").isEqualTo(200);
        assertThat(poll(login).path("status").asText()).isEqualTo("FAILED");
        assertAudited(WalletErrorCode.WALLET_ACCESS_DENIED);
    }

    // ============================================================================================ over-disclosure

    @Test
    void unrequestedClaim_sdJwt_isDropped_notRejected() throws Exception {
        final Login login = startLogin(newBrowser());
        final E2eHttp phone = newBrowser();
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(phone, WalletE2eFixture.scanQr(login.page()));
        final Map<String, Object> claims = new LinkedHashMap<>(sdJwtClaims("PAN-" + UUID.randomUUID()));
        claims.put("nationalities", List.of("DE")); // never requested by the default DCQL query

        assertThat(wallet.respond(phone, request, claims).status()).isEqualTo(200);
        final String next = poll(login).path("next").asText();
        final Finished finished = finishSignIn(login, next);

        final JsonNode userinfo = oidc().userinfo(finished.accessToken()).json();
        assertThat(userinfo.path("given_name").asText()).isEqualTo("Erika");
        assertThat(userinfo.has("nationalities")).as("dropped, never mapped: not in the default DCQL query")
                .isFalse();
    }

    @Test
    void unrequestedClaim_mdoc_isDropped_notRejected() throws Exception {
        final Login login = startLogin(newBrowser());
        final Oid4vpWalletClient.VerifiedRequest request =
                WalletE2eFixture.fetchRequest(login.browser(), WalletE2eFixture.openWalletLink(login.page()));
        final Map<String, Object> claims = new LinkedHashMap<>(mdocClaims("PAN-" + UUID.randomUUID()));
        claims.put("nationality", List.of("DE")); // never requested by the default DCQL query

        final E2eHttp.Response posted = wallet.respondWith(login.browser(), request, wallet.mdocVpToken(request, claims));
        assertThat(posted.status()).as(posted.toString()).isEqualTo(200);
        final Finished finished = finishSignIn(login, posted.json().path("redirect_uri").asText());

        final JsonNode userinfo = oidc().userinfo(finished.accessToken()).json();
        assertThat(userinfo.path("given_name").asText()).isEqualTo("Erika");
        assertThat(userinfo.has("nationalities")).as("dropped, never mapped: not in the default DCQL query")
                .isFalse();
    }

    // ============================================================================================ helpers

    private static Map<String, Object> sdJwtClaims(final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1984-01-26");
        claims.put("issuing_country", "DE");
        claims.put("personal_administrative_number", number);
        return claims;
    }

    /** mdoc element identifiers (not SD-JWT claim names): {@code birth_date}, not {@code birthdate}. */
    private static Map<String, Object> mdocClaims(final String number) {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birth_date", "1984-01-26");
        claims.put("issuing_country", "DE");
        claims.put("personal_administrative_number", number);
        return claims;
    }

    private record Login(E2eHttp browser, OidcFlow.Pkce pkce, String pageLocation, String page) {
    }

    private record Finished(String subject, String accessToken, String acr) {
    }

    private Login startLogin(final E2eHttp browser) {
        final OidcFlow.Pkce pkce = OidcFlow.Pkce.create();
        final String authorize = "/realms/" + realm + "/oauth2/authorize?response_type=code&client_id=web"
                + "&redirect_uri=" + E2eSeed.REDIRECT_URI + "&scope=openid%20profile&state=st&code_challenge="
                + pkce.challenge() + "&code_challenge_method=S256";
        final E2eHttp.Response loginPage = browser.followRedirects(browser.get(authorize, "Accept", "text/html"));
        assertThat(loginPage.body()).contains("/broker/" + alias);
        final E2eHttp.Response start = browser.get("/realms/" + realm + "/broker/" + alias);
        assertThat(start.status()).as(start.toString()).isEqualTo(302);
        final URI location = start.location();
        assertThat(location.getPath()).isEqualTo("/realms/" + realm + "/broker/" + alias + "/wallet");
        final String pageLocation = location.getPath() + "?" + location.getRawQuery();
        final E2eHttp.Response page = browser.get(pageLocation);
        assertThat(page.status()).as(page.toString()).isEqualTo(200);
        return new Login(browser, pkce, pageLocation, page.body());
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

    private OidcFlow oidc() {
        return new OidcFlow(newBrowser(), realm);
    }

    /** Follows the callback to the client, redeems the code and returns the tokens' subject/access token/acr. */
    private Finished finishSignIn(final Login login, final String callback) {
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
            return new Finished(id.getSubject(), tokens.accessToken(), id.getStringClaim("acr"));
        } catch (final java.text.ParseException e) {
            throw new AssertionError(e);
        }
    }

    private static void assertRejected(final E2eHttp.Response posted) {
        assertThat(posted.status()).as(posted.toString()).isEqualTo(400);
        assertThat(posted.json().path("error").asText()).isEqualTo("invalid_request");
    }

    /**
     * Waits (persistence is off the request thread, {@link AuditLog#emit}) for a {@code WALLET_LOGIN_FAILURE} audit
     * record of this test's realm whose detail carries {@code reason=code}.
     */
    private void assertAudited(final WalletErrorCode code) {
        final AuditLogService service = context.getBean(AuditLogService.class);
        final String marker = "\"reason\":\"" + code.name() + "\"";
        final Instant deadline = Instant.now().plusSeconds(5);
        List<AuditRecord> seen = List.of();
        while (Instant.now().isBefore(deadline)) {
            seen = service.search(new AuditQuery(realm, "WALLET_LOGIN_FAILURE", null, "FAILURE", null, 0, 100)).items();
            if (seen.stream().anyMatch(r -> r.detail() != null && r.detail().contains(marker))) {
                return;
            }
            try {
                Thread.sleep(25);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        throw new AssertionError("no WALLET_LOGIN_FAILURE audit with reason=" + code.name() + " in realm " + realm
                + "; seen=" + seen);
    }
}
