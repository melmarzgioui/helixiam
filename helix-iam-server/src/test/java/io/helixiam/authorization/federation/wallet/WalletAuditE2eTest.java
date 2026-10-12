/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.amqp.federation.FederatedIdentityPublisher;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.spi.IdentityProvider;
import io.helixiam.authorization.federation.wallet.testwallet.Oid4vpWalletClient;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestWallet;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * Task 22: every spec &sect;15 rejection yields a distinct {@link WalletErrorCode} AND a {@code WALLET_LOGIN_FAILURE}
 * audit event — pinned here by driving the real {@link WalletResponseHandler} / {@link WalletIdentityProvider}
 * pipeline and capturing the {@link AuditLog#emit} calls. The successful-login audit ({@code WALLET_LOGIN_SUCCESS})
 * is pinned in {@code WalletLoginCompleterTest} instead, at the point the login actually completes.
 *
 * <p>&sect;15's "unrequested-claim over-disclosure" is deliberately NOT a case here: the spec is explicit that an
 * over-disclosed claim is dropped, not rejected, so it never fails the transaction and never audits a
 * {@code WALLET_LOGIN_FAILURE} ({@code DcqlResultMatcherTest} already covers the drop itself).
 */
class WalletAuditE2eTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String BASE = "https://helix.example";
    private static final String HELIX_STATE = "helix-state-1";
    private static final String BINDING = "binding-hash-1";

    private static final TestPki ACCESS_PKI = TestPki.create("Audit Handler Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestWallet WALLET = TestWallet.create();

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100,
            null);
    private final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
    private final FederatedIdentityPublisher identities = mock(FederatedIdentityPublisher.class);
    private final RealmWalletPepper pepper = mock(RealmWalletPepper.class);
    private final AuditLog audit = mock(AuditLog.class);
    private final WalletResponseHandler handler;

    WalletAuditE2eTest() {
        when(pepper.pepper(any())).thenReturn(new byte[32]);
        handler = new WalletResponseHandler(new WalletSubjectResolver(pepper), new WalletLinkService(identities),
                AccountLinkingPolicy.defaults(), BASE, audit);
    }

    private WalletIdentityProvider provider() {
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", WALLET.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\"]");
        return new WalletIdentityProviders(new WalletConfigValidator(keys, DeploymentProfile.production()), keys,
                store, new OutboundUrlGuard(), audit)
                .build(REALM, WalletProviderConfig.fromStored(ALIAS, "Wallet", config));
    }

    /** The same provider, its real verifier for {@code dc+sd-jwt} swapped for one that always throws {@code code}. */
    private WalletIdentityProvider withFakeVerifier(final WalletIdentityProvider real, final WalletErrorCode code) {
        return new WalletIdentityProvider(real.config(), REALM, real.signingKey(), real.trustAnchors(),
                real.statusPolicy(), real.statusClient(), Map.of("dc+sd-jwt", new ThrowingVerifier(code)),
                real.transactions(), Clock.systemUTC(), audit);
    }

    /** Always throws {@code code} for {@code dc+sd-jwt} — the real pipeline (claim/decrypt/DCQL/fail/audit) is real. */
    private record ThrowingVerifier(WalletErrorCode code) implements PresentationVerifier {
        @Override
        public String format() {
            return "dc+sd-jwt";
        }

        @Override
        public VerifiedPresentation verify(final String rawPresentation, final VerificationContext context) {
            throw new WalletVerificationException(code, "test: forced " + code);
        }
    }

    private Oid4vpWalletClient.VerifiedRequest fetched(final WalletIdentityProvider provider,
                                                       final WalletTransaction.Flow flow) {
        final IdentityProvider.AuthnRequestContext context = new IdentityProvider.AuthnRequestContext(
                REALM, HELIX_STATE, BASE + "/realms/acme/broker/eudi-wallet/callback", BINDING);
        final IdentityProvider.RedirectResponse redirect = provider.start(context);
        final String txId = redirect.location().substring(redirect.location().indexOf("tx=") + 3);
        final WalletTransaction created = store.byTransactionId(txId).orElseThrow();
        final WalletTransaction tx = store.claimRequest(flow == WalletTransaction.Flow.SAME_DEVICE
                ? created.sameDeviceRequestId() : created.crossDeviceRequestId()).orElseThrow();
        final String jwt = new AuthorizationRequestFactory().signedRequestObject(tx, provider.config(),
                provider.signingKey(), BASE);
        return Oid4vpWalletClient.verifyRequest(provider.clientId(),
                AuthorizationRequestFactory.requestUri(BASE, tx, flow), jwt, Instant.now());
    }

    private static Map<String, String[]> form(final String... pairs) {
        final Map<String, String[]> form = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            form.put(pairs[i], new String[] {pairs[i + 1]});
        }
        return form;
    }

    private static String responseId(final Oid4vpWalletClient.VerifiedRequest request) {
        return request.responseUri().substring(request.responseUri().lastIndexOf('/') + 1);
    }

    private static Map<String, Object> dummyVpToken() {
        return Map.of("pid_sd_jwt", List.of("dummy-presentation"));
    }

    private AuditEvent soleFailureEvent() {
        final ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        org.mockito.Mockito.verify(audit, org.mockito.Mockito.atLeastOnce()).emit(captor.capture());
        final List<AuditEvent> failures = captor.getAllValues().stream()
                .filter(e -> "WALLET_LOGIN_FAILURE".equals(e.type())).toList();
        assertThat(failures).as("exactly one WALLET_LOGIN_FAILURE, never double-counted").hasSize(1);
        return failures.get(0);
    }

    // ------------------------------------------------------------------------------------- content-level rejections

    /**
     * Tampered issuer signature, untrusted issuer, expired credential, revoked credential, wrong nonce, wrong aud and
     * missing KB-JWT all surface through the same verifier failure path: each maps to its own
     * {@link WalletErrorCode} and audits a distinct {@code WALLET_LOGIN_FAILURE} with that reason.
     */
    @ParameterizedTest
    @EnumSource(value = WalletErrorCode.class, names = {"ISSUER_SIGNATURE_INVALID", "ISSUER_UNTRUSTED",
            "CREDENTIAL_EXPIRED", "CREDENTIAL_REVOKED", "NONCE_MISMATCH", "AUDIENCE_MISMATCH",
            "HOLDER_BINDING_MISSING"})
    void everyContentRejection_mapsToItsOwnCode_andAuditsAFailure(final WalletErrorCode code) {
        final WalletIdentityProvider real = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(real, WalletTransaction.Flow.CROSS_DEVICE);
        final WalletIdentityProvider provider = withFakeVerifier(real, code);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("response", Oid4vpWalletClient.respond(request, dummyVpToken())));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Rejected(code));
        final AuditEvent event = soleFailureEvent();
        assertThat(event.outcome()).isEqualTo("FAILURE");
        assertThat(event.detail()).containsEntry("reason", code.name()).containsEntry("alias", ALIAS)
                .containsEntry("format", "dc+sd-jwt").doesNotContainKey("issuerDn");
        assertThat(event.detail()).containsKey("transactionId");
    }

    // ------------------------------------------------------------------------------------------------ wallet-reported

    @Test
    void walletAccessDenied_mapsToItsOwnCode_distinctFromAnyOtherWalletError() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("error", "access_denied", "state", request.state()));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.WalletErrorRecorded());
        final AuditEvent event = soleFailureEvent();
        assertThat(event.detail()).containsEntry("reason", "WALLET_ACCESS_DENIED");
    }

    @Test
    void replayedResponse_isFailed_andAuditedOnce_notTwice() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
        final Map<String, String[]> form = form("response", Oid4vpWalletClient.respond(request, vpToken(request)));
        handler.handle(provider, REALM, responseId(request), form); // first POST: verified

        final WalletResponseHandler.Result second = handler.handle(provider, REALM, responseId(request), form);

        assertThat(second).isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.REPLAY));
        // the first POST succeeded (no failure audit); the replayed second one audits exactly one REPLAY failure
        final AuditEvent event = soleFailureEvent();
        assertThat(event.detail()).containsEntry("reason", "REPLAY");
    }

    @Test
    void transactionExpiredBetweenClaimAndComplete_isFailed_andAudited() {
        final WalletIdentityProvider real = provider();
        final WalletTransactionStore spyStore = spy(real.transactions());
        when(spyStore.complete(any(), any(), any())).thenReturn(false); // simulate expiry winning the race
        final WalletIdentityProvider provider = new WalletIdentityProvider(real.config(), REALM, real.signingKey(),
                real.trustAnchors(), real.statusPolicy(), real.statusClient(), verifiersOf(real), spyStore,
                Clock.systemUTC(), audit);
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("response", Oid4vpWalletClient.respond(request, vpToken(request))));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.TRANSACTION_EXPIRED));
        final AuditEvent event = soleFailureEvent();
        assertThat(event.detail()).containsEntry("reason", "TRANSACTION_EXPIRED");
    }

    private static Map<String, PresentationVerifier> verifiersOf(final WalletIdentityProvider provider) {
        return provider.verifiers();
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

    private static Map<String, Object> vpToken(final Oid4vpWalletClient.VerifiedRequest request) {
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential credential = WALLET.sdJwtPid(pid(), now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        return Map.of("pid_sd_jwt", List.of(WALLET.present(credential, pid().keySet(), request.clientId(),
                request.nonce())));
    }

    // -------------------------------------------------------------------------------------------- callback (redeem)

    private WalletIdentityProvider callbackProvider() {
        return provider();
    }

    /** Drives a transaction to VERIFIED without a real presentation (the callback path never looks at content). */
    private WalletTransaction verifiedTransaction(final WalletIdentityProvider provider, final String binding) {
        final IdentityProvider.AuthnRequestContext context = new IdentityProvider.AuthnRequestContext(REALM,
                HELIX_STATE, BASE + "/realms/acme/broker/eudi-wallet/callback", binding);
        final IdentityProvider.RedirectResponse redirect = provider.start(context);
        final String txId = redirect.location().substring(redirect.location().indexOf("tx=") + 3);
        final WalletTransaction created = store.byTransactionId(txId).orElseThrow();
        final WalletTransaction claimed = store.claimRequest(created.crossDeviceRequestId()).orElseThrow();
        store.claimResponse(claimed.responseId());
        final String identityJson = VerifiedIdentityJson.write(
                new io.helixiam.authorization.federation.spi.BrokeredIdentity(ALIAS, "s".repeat(64), null, false,
                        Map.of(), "http://eidas.europa.eu/LoA/high"),
                new WalletLinkService.Decision.Existing("user-1"));
        store.complete(txId, null, identityJson);
        return store.byTransactionId(txId).orElseThrow();
    }

    @Test
    void redeemFromAnotherBrowserSession_isBrowserMismatch_andAudited() {
        final WalletIdentityProvider provider = callbackProvider();
        final WalletTransaction tx = verifiedTransaction(provider, "binding-A");
        final String code = store.issueResponseCode(tx.transactionId(), "binding-A").orElseThrow();

        // Another browser session never began this (or any) wallet login, so it holds no binding at all —
        // BrowserBinding.current(session, alias) is exactly this: null/blank for a session that never started one.
        assertThatRefusalIsAudited(provider, code, HELIX_STATE, null, WalletErrorCode.BROWSER_MISMATCH);
    }

    @Test
    void reusedResponseCode_isReplay_andAuditedOnce() {
        final WalletIdentityProvider provider = callbackProvider();
        final WalletTransaction tx = verifiedTransaction(provider, "binding-A");
        final String code = store.issueResponseCode(tx.transactionId(), "binding-A").orElseThrow();
        // First redemption succeeds (not audited as a failure).
        provider.callback(new IdentityProvider.CallbackContext(REALM,
                Map.of(WalletIdentityProvider.RESPONSE_CODE_PARAM, code), HELIX_STATE, null, null, null,
                "binding-A"));

        // Redeeming the same (now spent) code again is a replay.
        assertThatRefusalIsAudited(provider, code, HELIX_STATE, "binding-A", WalletErrorCode.REPLAY);
    }

    private void assertThatRefusalIsAudited(final WalletIdentityProvider provider, final String code,
                                            final String state, final String binding, final WalletErrorCode expected) {
        final IdentityProvider.CallbackContext context = new IdentityProvider.CallbackContext(REALM,
                Map.of(WalletIdentityProvider.RESPONSE_CODE_PARAM, code), state, null, null, null, binding);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> provider.callback(context))
                .isInstanceOf(WalletVerificationException.class)
                .satisfies(e -> assertThat(((WalletVerificationException) e).code()).isEqualTo(expected));
        final AuditEvent event = soleFailureEvent();
        assertThat(event.detail()).containsEntry("reason", expected.name()).containsEntry("alias", ALIAS);
        // the callback path never carries presentation content: never a format/issuer DN here.
        assertThat(event.detail()).doesNotContainKey("format").doesNotContainKey("issuerDn");
    }
}
