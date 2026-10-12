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
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;

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
import static org.mockito.Mockito.when;

/**
 * Task 18: the response endpoint's pipeline (the wallet's POST, no user session): claim → decrypt or (dev) strict
 * {@code vp_token} → state → DCQL + verification → mapping → subject + decision → complete / fail. Driven with the
 * test wallet against a real provider over an in-memory store; the link store is a mock.
 */
class WalletResponseHandlerTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String BASE = "https://helix.example";
    private static final String HELIX_STATE = "helix-state-1";
    private static final String BINDING = "binding-hash-1";

    private static final TestPki ACCESS_PKI = TestPki.create("Handler Access");
    private static final TestPki.Leaf ACCESS = ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestWallet WALLET = TestWallet.create();

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100);
    private final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
    private final FederatedIdentityPublisher identities = mock(FederatedIdentityPublisher.class);
    private final RealmWalletPepper pepper = mock(RealmWalletPepper.class);
    private final WalletResponseHandler handler;
    /** The transaction of the last {@link #fetched} login (its id never reaches the wallet). */
    private String lastTxId;

    WalletResponseHandlerTest() {
        when(pepper.pepper(any())).thenReturn(new byte[32]);
        handler = new WalletResponseHandler(new WalletSubjectResolver(pepper), new WalletLinkService(identities),
                AccountLinkingPolicy.defaults(), BASE);
    }

    private WalletIdentityProvider provider(final DeploymentProfile profile, final Map<String, String> extra) {
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", WALLET.pki().rootPem());
        config.put("revocationChecking", "OFF");
        config.put("credentialFormats", "[\"dc+sd-jwt\"]");
        config.putAll(extra);
        return new WalletIdentityProviders(new WalletConfigValidator(keys, profile), keys, store,
                new OutboundUrlGuard(), mock(AuditLog.class))
                .build(REALM, WalletProviderConfig.fromStored(ALIAS, "Wallet", config));
    }

    private WalletIdentityProvider provider() {
        return provider(DeploymentProfile.production(), Map.of());
    }

    /** Starts a login and lets the wallet fetch the {@code flow}'s request object. */
    private Oid4vpWalletClient.VerifiedRequest fetched(final WalletIdentityProvider provider,
                                                      final WalletTransaction.Flow flow) {
        final IdentityProvider.RedirectResponse redirect = provider.start(new IdentityProvider.AuthnRequestContext(
                REALM, HELIX_STATE, BASE + "/realms/acme/broker/eudi-wallet/callback", BINDING));
        final String txId = redirect.location().substring(redirect.location().indexOf("tx=") + 3);
        lastTxId = txId;
        final WalletTransaction created = store.byTransactionId(txId).orElseThrow();
        final WalletTransaction tx = store.claimRequest(flow == WalletTransaction.Flow.SAME_DEVICE
                ? created.sameDeviceRequestId() : created.crossDeviceRequestId()).orElseThrow();
        final String jwt = new AuthorizationRequestFactory().signedRequestObject(tx, provider.config(),
                provider.signingKey(), BASE);
        return Oid4vpWalletClient.verifyRequest(provider.clientId(),
                AuthorizationRequestFactory.requestUri(BASE, tx, flow), jwt, Instant.now());
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

    private WalletTransaction tx(final Oid4vpWalletClient.VerifiedRequest request) {
        assertThat(request.state()).isEqualTo(AuthorizationRequestFactory.walletState(lastTxId));
        return store.byTransactionId(lastTxId).orElseThrow();
    }

    // ------------------------------------------------------------------------------------------------ success

    @Test
    void crossDevice_encryptedResponse_completesWithoutACode_andAnswersNoRedirect() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("response", Oid4vpWalletClient.respond(request, vpToken(request))));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Accepted(null));
        final WalletTransaction tx = tx(request);
        assertThat(tx.status()).isEqualTo(WalletTransaction.Status.VERIFIED);
        assertThat(tx.encryptionJwkJson()).isNull();
        final VerifiedIdentityJson.StoredLogin stored = VerifiedIdentityJson.readLogin(ALIAS, tx.verifiedIdentityJson());
        assertThat(stored.decision()).isEqualTo(new WalletLinkService.Decision.Provision());
        assertThat(stored.identity().attributes()).containsEntry("given_name", "Erika")
                .doesNotContainKey("personal_administrative_number");
        assertThat(stored.identity().externalSubject()).matches("[0-9a-f]{64}");
        assertThat(tx.verifiedIdentityJson()).as("never the vp_token or the number").doesNotContain("~")
                .doesNotContain("PAN-0001");
        assertThat(store.issueResponseCode(tx.transactionId(), BINDING)).isPresent();
    }

    @Test
    void sameDevice_answersTheCallbackWithAFreshCode() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.SAME_DEVICE);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("response", Oid4vpWalletClient.respond(request, vpToken(request))));

        final String redirect = ((WalletResponseHandler.Result.Accepted) result).redirectUri();
        assertThat(redirect).startsWith(BASE + "/realms/acme/broker/eudi-wallet/callback?response_code=")
                .endsWith("&state=" + HELIX_STATE);
        final String code = redirect.substring(redirect.indexOf("response_code=") + 14, redirect.indexOf("&state"));
        assertThat(code).matches("[A-Za-z0-9_-]{22,}");
        assertThat(store.redeem(code, HELIX_STATE, BINDING)).isPresent();
    }

    @Test
    void devDirectPost_parsesTheVpTokenStrictly() {
        final WalletIdentityProvider provider = provider(DeploymentProfile.development(),
                Map.of("responseMode", "direct_post"));
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("vp_token", TestWallet.json(vpToken(request)), "state", request.state()));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Accepted(null));
    }

    @Test
    void devDirectPost_refusesDuplicateMembersInTheVpToken() {
        final WalletIdentityProvider provider = provider(DeploymentProfile.development(),
                Map.of("responseMode", "direct_post"));
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
        final String presentation = ((List<?>) vpToken(request).get("pid_sd_jwt")).get(0).toString();
        final String duplicated = "{\"pid_sd_jwt\":[\"" + presentation + "\"],\"pid_sd_jwt\":[\"x\"]}";

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("vp_token", duplicated, "state", request.state()));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.INVALID_RESPONSE));
        assertThat(tx(request).status()).isEqualTo(WalletTransaction.Status.FAILED);
        assertThat(tx(request).failureCode()).isEqualTo(WalletErrorCode.INVALID_RESPONSE);
    }

    // ------------------------------------------------------------------------------------------------ refusals

    @Test
    void anUnencryptedVpToken_isRefused_whenTheProviderWantsDirectPostJwt() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        final WalletResponseHandler.Result result = handler.handle(provider, REALM, responseId(request),
                form("vp_token", TestWallet.json(vpToken(request)), "state", request.state()));

        assertThat(result).isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.INVALID_RESPONSE));
        assertThat(tx(request).status()).isEqualTo(WalletTransaction.Status.FAILED);
    }

    @Test
    void aSecondResponse_isAReplay_andLeavesTheFirstOutcome() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
        final Map<String, String[]> form = form("response", Oid4vpWalletClient.respond(request, vpToken(request)));
        handler.handle(provider, REALM, responseId(request), form);

        assertThat(handler.handle(provider, REALM, responseId(request), form))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.REPLAY));
        assertThat(tx(request).status()).isEqualTo(WalletTransaction.Status.VERIFIED);
    }

    @Test
    void aWalletErrorResponse_failsTheTransaction_andIsAcknowledged() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        assertThat(handler.handle(provider, REALM, responseId(request),
                form("error", "access_denied", "error_description", "user said no", "state", request.state())))
                .isEqualTo(new WalletResponseHandler.Result.WalletErrorRecorded());
        assertThat(tx(request).status()).isEqualTo(WalletTransaction.Status.FAILED);
        assertThat(tx(request).failureCode()).isEqualTo(WalletErrorCode.WALLET_ERROR);
    }

    @Test
    void aWrongState_failsWithStateMismatch() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        assertThat(handler.handle(provider, REALM, responseId(request), form("error", "access_denied", "state", "x")))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.STATE_MISMATCH));
        assertThat(tx(request).failureCode()).isEqualTo(WalletErrorCode.STATE_MISMATCH);
    }

    @Test
    void aRepeatedFormParameter_isRefusedBeforeTheTransactionIsTouched() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
        final Map<String, String[]> form = new LinkedHashMap<>();
        form.put("response", new String[] {"a", "b"});

        assertThat(handler.handle(provider, REALM, responseId(request), form))
                .isEqualTo(new WalletResponseHandler.Result.Rejected(WalletErrorCode.INVALID_RESPONSE));
        assertThat(tx(request).status()).isEqualTo(WalletTransaction.Status.REQUEST_FETCHED);
    }

    @Test
    void anotherRealm_isNotFound_andTheTransactionIsFailed() {
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        assertThat(handler.handle(provider, "other", responseId(request),
                form("response", Oid4vpWalletClient.respond(request, vpToken(request)))))
                .isEqualTo(new WalletResponseHandler.Result.NotFound());
        assertThat(tx(request).status()).isEqualTo(WalletTransaction.Status.FAILED);
    }

    @Test
    void aSubjectThatNeedsALink_isStoredAsRefused_withoutAnyIdentity() {
        final WalletIdentityProvider provider = provider(DeploymentProfile.production(),
                Map.of("subject.acknowledgeWeakSubject", "true"));
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);
        final Map<String, Object> noNumber = new LinkedHashMap<>(pid());
        noNumber.remove("personal_administrative_number");
        final Instant now = Instant.now();
        final TestWallet.SdJwtCredential credential = WALLET.sdJwtPid(noNumber, now.minusSeconds(60),
                now.plusSeconds(3600), Optional.empty());
        final Map<String, Object> token = Map.of("pid_sd_jwt", List.of(WALLET.present(credential, noNumber.keySet(),
                request.clientId(), request.nonce())));

        assertThat(handler.handle(provider, REALM, responseId(request),
                form("response", Oid4vpWalletClient.respond(request, token))))
                .isEqualTo(new WalletResponseHandler.Result.Accepted(null));
        final VerifiedIdentityJson.StoredLogin stored =
                VerifiedIdentityJson.readLogin(ALIAS, tx(request).verifiedIdentityJson());
        assertThat(stored.decision()).isEqualTo(
                new WalletLinkService.Decision.Refused(WalletSubject.Reason.LINK_REQUIRED));
        assertThat(stored.identity()).isNull();
        assertThat(tx(request).verifiedIdentityJson()).doesNotContain("Erika");
    }

    @Test
    void anExistingLink_isStoredAsExisting() {
        when(identities.findRealmLinkedUser(any())).thenReturn("user-7");
        final WalletIdentityProvider provider = provider();
        final Oid4vpWalletClient.VerifiedRequest request = fetched(provider, WalletTransaction.Flow.CROSS_DEVICE);

        handler.handle(provider, REALM, responseId(request),
                form("response", Oid4vpWalletClient.respond(request, vpToken(request))));

        assertThat(VerifiedIdentityJson.readLogin(ALIAS, tx(request).verifiedIdentityJson()).decision())
                .isEqualTo(new WalletLinkService.Decision.Existing("user-7"));
    }
}
