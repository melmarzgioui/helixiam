/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.wallet.testwallet.DcApiWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link WalletResponseHandler#handleDcApi}: the login page posts the {@code DigitalCredential} the browser returned.
 * Driven with the test wallet's DC API side ({@link DcApiWalletClient}) against a real provider over an in-memory
 * store. The origin is the one the platform would report; the server's expected origin comes from its base URL.
 */
class WalletDcApiResponseHandlerTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String BASE = "https://helix.example";
    private static final String ORIGIN = "https://helix.example";
    private static final String BINDING = "binding-hash-1";

    private static final TestPki ACCESS_PKI = TestPki.create("DC API Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestWallet WALLET = TestWallet.create();

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100);
    private final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
    private final RealmWalletPepper pepper = mock(RealmWalletPepper.class);
    private final AuditLog audit = mock(AuditLog.class);
    private final WalletResponseHandler handler;

    WalletDcApiResponseHandlerTest() {
        when(pepper.pepper(any())).thenReturn(new byte[32]);
        handler = new WalletResponseHandler(new WalletSubjectResolver(pepper),
                new WalletLinkService(mock(FederatedIdentityPublisher.class)), AccountLinkingPolicy.defaults(), BASE,
                audit);
    }

    private WalletIdentityProvider provider(final DeploymentProfile profile, final Map<String, String> extra) {
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", WALLET.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\",\"mso_mdoc\"]");
        config.put("dcApi.enabled", "true");
        config.putAll(extra);
        return new WalletIdentityProviders(new WalletConfigValidator(keys, profile), keys, store,
                new OutboundUrlGuard(), mock(AuditLog.class))
                .build(REALM, WalletProviderConfig.fromStored(ALIAS, "Wallet", config));
    }

    private WalletIdentityProvider provider() {
        return provider(DeploymentProfile.production(), Map.of());
    }

    private WalletTransaction started(final WalletIdentityProvider provider) {
        final IdentityProvider.RedirectResponse redirect = provider.start(new IdentityProvider.AuthnRequestContext(
                REALM, "helix-state", BASE + "/realms/acme/broker/eudi-wallet/callback", BINDING));
        return store.byTransactionId(redirect.location().substring(redirect.location().indexOf("tx=") + 3))
                .orElseThrow();
    }

    /** What the browser hands the wallet, and the wallet accepts, at {@code origin}. */
    private static DcApiWalletClient.DcApiRequest asWallet(final WalletIdentityProvider provider,
                                                           final WalletTransaction tx, final String origin) {
        final AuthorizationRequestFactory.DcApiRequest request = new AuthorizationRequestFactory().dcApiRequest(tx,
                provider.config(), provider.signingKey(), List.of(ORIGIN));
        return DcApiWalletClient.verify(request.protocol(), request.data(), origin, Instant.now());
    }

    private static Map<String, Object> pid() {
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birthdate", "1984-01-26");
        claims.put("issuing_country", "DE");
        claims.put("personal_administrative_number", "PAN-0001");
        return claims;
    }

    private static Map<String, Object> sdJwtVpToken(final String aud, final String nonce) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential credential = WALLET.sdJwtPid(pid(), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        return Map.of("pid_sd_jwt", List.of(WALLET.present(credential, pid().keySet(), aud, nonce)));
    }

    private static Map<String, Object> mdocVpToken(final byte[] transcript) {
        final Instant now = Instant.now();
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("given_name", "Erika");
        claims.put("family_name", "Mustermann");
        claims.put("birth_date", new TestWallet.CborTag(1004, "1984-01-26"));
        claims.put("issuing_country", "DE");
        claims.put("personal_administrative_number", "PAN-0001");
        final TestWallet.MdocCredential credential = WALLET.mdocPid(claims, now.minusSeconds(60),
                now.minusSeconds(60), now.plusSeconds(3600), Optional.empty());
        return Map.of("pid_mdoc", List.of(TestWallet.b64url(TestWallet.mdocDeviceResponse(credential,
                claims.keySet(), transcript))));
    }

    private static String body(final String protocol, final Map<String, Object> data) {
        return TestWallet.json(Map.of("protocol", protocol, "data", data));
    }

    private WalletTransaction current(final WalletTransaction tx) {
        return store.byTransactionId(tx.transactionId()).orElseThrow();
    }

    // ------------------------------------------------------------------ success

    @Test
    void signed_sdJwt_boundToTheOrigin_isVerified_andCompletedWithoutACode() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);

        final WalletResponseHandler.Result result = handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, sdJwtVpToken(request.audience(), request.nonce()))));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Accepted(null));
        final WalletTransaction done = current(tx);
        assertThat(done.status()).isEqualTo(WalletTransaction.Status.VERIFIED);
        assertThat(done.flow()).isEqualTo(WalletTransaction.Flow.DC_API);
        assertThat(store.issueResponseCode(tx.transactionId(), BINDING)).isPresent();
    }

    @Test
    void mdoc_overTheDcApiTranscript_isVerified() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);

        final WalletResponseHandler.Result result = handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, mdocVpToken(request.sessionTranscript()))));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Accepted(null));
    }

    @Test
    void unsigned_isVerifiedToo() {
        final WalletIdentityProvider provider = provider(DeploymentProfile.production(),
                Map.of("dcApi.request", "unsigned"));
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);

        assertThat(request.protocol()).isEqualTo("openid4vp-v1-unsigned");
        assertThat(handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, sdJwtVpToken(request.audience(), request.nonce())))))
                .isEqualTo(new WalletResponseHandler.Result.Accepted(null));
    }

    @Test
    void devPlainDcApi_takesAnUnencryptedVpToken() {
        final WalletIdentityProvider provider = provider(DeploymentProfile.development(),
                Map.of("responseMode", "direct_post"));
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);

        assertThat(request.responseMode()).isEqualTo("dc_api");
        assertThat(handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, mdocVpToken(request.sessionTranscript())))))
                .isEqualTo(new WalletResponseHandler.Result.Accepted(null));
    }

    // ------------------------------------------------------------------ origin binding

    @Test
    void anUnsignedRequestAnsweredForAnotherOrigin_isRefused_andFailsTheTransaction() {
        // Unsigned: the wallet accepts any origin; the presentation is then bound to that origin, not ours.
        final WalletIdentityProvider provider = provider(DeploymentProfile.production(),
                Map.of("dcApi.request", "unsigned"));
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest atEvil = asWallet(provider, tx, "https://evil.example.com");

        final WalletResponseHandler.Result result = handler.handleDcApi(provider, REALM, tx, body(atEvil.protocol(),
                DcApiWalletClient.respond(atEvil, sdJwtVpToken(atEvil.audience(), atEvil.nonce()))));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.AUDIENCE_MISMATCH));
        assertThat(current(tx).status()).isEqualTo(WalletTransaction.Status.FAILED);
        final ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit, atLeastOnce()).emit(events.capture());
        assertThat(events.getValue().type()).isEqualTo("WALLET_LOGIN_FAILURE");
        assertThat(events.getValue().detail()).containsEntry("reason", "AUDIENCE_MISMATCH")
                .containsEntry("invocation", "dc_api").containsEntry("transactionId", tx.transactionId());
    }

    @Test
    void anMdocBoundToAnotherOrigin_isRefused() {
        final WalletIdentityProvider provider = provider(DeploymentProfile.production(),
                Map.of("dcApi.request", "unsigned"));
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest atEvil = asWallet(provider, tx, "https://evil.example.com");

        assertThat(handler.handleDcApi(provider, REALM, tx, body(atEvil.protocol(),
                DcApiWalletClient.respond(atEvil, mdocVpToken(atEvil.sessionTranscript())))))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.HOLDER_BINDING_INVALID));
    }

    @Test
    void aPresentationBoundToTheClientId_isRefused() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);

        assertThat(handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, sdJwtVpToken(provider.clientId(), request.nonce())))))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.AUDIENCE_MISMATCH));
    }

    // ------------------------------------------------------------------ single use / wrong transaction

    @Test
    void aReplay_isRefused_andTheFirstResultStands() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);
        final String body = body(request.protocol(),
                DcApiWalletClient.respond(request, sdJwtVpToken(request.audience(), request.nonce())));

        assertThat(handler.handleDcApi(provider, REALM, tx, body))
                .isEqualTo(new WalletResponseHandler.Result.Accepted(null));
        assertThat(handler.handleDcApi(provider, REALM, tx, body))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.REPLAY));
        assertThat(current(tx).status()).isEqualTo(WalletTransaction.Status.VERIFIED);
    }

    @Test
    void anotherTransactionsResponse_isRefused() {
        // The nonce (and key) belong to transaction A; posting it as transaction B's answer cannot verify.
        final WalletIdentityProvider provider = provider();
        final WalletTransaction a = started(provider);
        final WalletTransaction b = started(provider);
        final DcApiWalletClient.DcApiRequest requestA = asWallet(provider, a, ORIGIN);

        final WalletResponseHandler.Result result = handler.handleDcApi(provider, REALM, b, body(requestA.protocol(),
                DcApiWalletClient.respond(requestA, sdJwtVpToken(requestA.audience(), requestA.nonce()))));

        assertThat(result).isInstanceOf(WalletResponseHandler.Result.Rejected.class);
        assertThat(current(b).status()).isEqualTo(WalletTransaction.Status.FAILED);
        assertThat(current(a).status()).isEqualTo(WalletTransaction.Status.CREATED);
    }

    @Test
    void aTransactionWhoseQrRequestWasFetched_cannotBeAnsweredOverTheDcApi() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);
        assertThat(store.claimRequest(tx.crossDeviceRequestId())).isPresent();

        assertThat(handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, sdJwtVpToken(request.audience(), request.nonce())))))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.REPLAY));
    }

    @Test
    void anotherRealmOrProvider_orTheDcApiOff_isNotFound() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);

        assertThat(handler.handleDcApi(provider, "other", tx, "{}")).isEqualTo(new WalletResponseHandler.Result.NotFound());
        final WalletIdentityProvider off = provider(DeploymentProfile.production(), Map.of("dcApi.enabled", "false"));
        assertThat(handler.handleDcApi(off, REALM, started(off), "{}"))
                .isEqualTo(new WalletResponseHandler.Result.NotFound());
        assertThat(current(tx).status()).isEqualTo(WalletTransaction.Status.CREATED);
    }

    // ------------------------------------------------------------------ body shape

    @Test
    void malformedBodies_areRefusedBeforeTheTransactionIsTouched() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final String protocol = "openid4vp-v1-signed";

        for (final String body : List.of("", "not json", "[]", "{\"protocol\":\"" + protocol + "\"}",
                "{\"protocol\":\"openid4vp-v1-unsigned\",\"data\":{\"response\":\"x\"}}",
                "{\"protocol\":\"" + protocol + "\",\"data\":{}}",
                "{\"protocol\":\"" + protocol + "\",\"data\":{\"response\":\"x\",\"error\":\"y\"}}",
                "{\"protocol\":\"" + protocol + "\",\"data\":{\"response\":\"x\",\"state\":\"y\"}}",
                "{\"protocol\":\"" + protocol + "\",\"data\":{\"response\":\"x\"},\"extra\":1}",
                "{\"protocol\":\"" + protocol + "\",\"protocol\":\"" + protocol + "\",\"data\":{\"response\":\"x\"}}",
                "{\"protocol\":\"" + protocol + "\",\"data\":{\"response\":5}}")) {
            assertThat(handler.handleDcApi(provider, REALM, tx, body)).as(body)
                    .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.INVALID_RESPONSE));
        }
        assertThat(current(tx).status()).isEqualTo(WalletTransaction.Status.CREATED);
    }

    @Test
    void anEncryptedProviderGivenAPlainVpToken_isRefused() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);

        assertThat(handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                Map.of("vp_token", sdJwtVpToken(request.audience(), request.nonce())))))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.INVALID_RESPONSE));
    }

    @Test
    void aWalletError_failsTheTransaction_asDeclined() {
        final WalletIdentityProvider provider = provider();
        final WalletTransaction tx = started(provider);

        assertThat(handler.handleDcApi(provider, REALM, tx, body("openid4vp-v1-signed",
                Map.of("error", "access_denied"))))
                .isEqualTo(new WalletResponseHandler.Result.WalletErrorRecorded());
        assertThat(current(tx).failureCode()).isEqualTo(WalletErrorCode.WALLET_ACCESS_DENIED);
    }

    // ------------------------------------------------------------------ verify-only (subject.strategy=NONE)

    private WalletIdentityProvider verifyOnly() {
        return provider(DeploymentProfile.production(), Map.of("subject.strategy", "NONE",
                "verify.linkedProvider", "eudi-login"));
    }

    private WalletTransaction verifyStarted(final WalletIdentityProvider provider) {
        final IdentityProvider.RedirectResponse redirect = provider.startVerify(new IdentityProvider.AuthnRequestContext(
                REALM, "helix-state", null, BINDING), "user-7");
        return store.byTransactionId(redirect.location().substring(redirect.location().indexOf("tx=") + 3))
                .orElseThrow();
    }

    @Test
    void aVerifyOnlyConnection_cannotStartASignIn_soTheDcApiNeverSignsAnyoneIn() {
        final WalletIdentityProvider provider = verifyOnly();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> started(provider))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void overTheDcApi_aVerificationIsStoredAsAVerification_andARefusalIsAuditedAsOne() {
        final WalletIdentityProvider provider = verifyOnly();
        final WalletTransaction tx = verifyStarted(provider);
        final DcApiWalletClient.DcApiRequest request = asWallet(provider, tx, ORIGIN);
        assertThat(handler.handleDcApi(provider, REALM, tx, body(request.protocol(),
                DcApiWalletClient.respond(request, sdJwtVpToken(request.audience(), request.nonce())))))
                .isEqualTo(new WalletResponseHandler.Result.Accepted(null));
        assertThat(VerifiedIdentityJson.readVerify(current(tx).verifiedIdentityJson())).isNotNull();
        assertThat(WalletIdentityProvider.callbackPath(current(tx))).isEqualTo("/flow/wallet/callback");

        final WalletTransaction other = verifyStarted(provider);
        final DcApiWalletClient.DcApiRequest second = asWallet(provider, other, ORIGIN);
        handler.handleDcApi(provider, REALM, other, body(second.protocol(),
                DcApiWalletClient.respond(second, sdJwtVpToken("origin:https://evil.example", second.nonce()))));
        final org.mockito.ArgumentCaptor<io.helixiam.authorization.security.audit.AuditEvent> events =
                org.mockito.ArgumentCaptor.forClass(io.helixiam.authorization.security.audit.AuditEvent.class);
        org.mockito.Mockito.verify(audit, org.mockito.Mockito.atLeastOnce()).emit(events.capture());
        assertThat(events.getValue().type()).isEqualTo("WALLET_VERIFY_FAILURE");
        assertThat(events.getValue().actor()).isEqualTo("user-7");
    }
}
