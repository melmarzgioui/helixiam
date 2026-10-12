/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.web;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import io.helixiam.authorization.federation.wallet.WalletResponseHandler;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransactionStore;
import io.helixiam.authorization.security.flow.BrowserBinding;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.key.SigningKeyHandle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Task 18 fix round 1: the request endpoint after a claim, and the status names the bound browser sees. */
class WalletWebControllersTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";

    private final IdentityProviderRegistry registry = mock(IdentityProviderRegistry.class);
    private final WalletIdentityProvider provider = mock(WalletIdentityProvider.class);
    private final WalletTransactionStore store = mock(WalletTransactionStore.class);

    @BeforeEach
    void setUp() {
        RealmContextHolder.set(REALM);
        when(registry.get(ALIAS)).thenReturn(provider);
        when(provider.transactions()).thenReturn(store);
        when(provider.config()).thenReturn(WalletProviderConfig.fromStored(ALIAS, "Wallet",
                Map.of("accessKeyRef", "software:acme/a", "trustAnchors", "x")));
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    private static WalletTransaction tx(final WalletTransaction.Status status, final String binding) {
        final Instant now = Instant.now();
        return new WalletTransaction("tx-1", "sd", "cd", "resp", REALM, ALIAS, "helix-state", binding, "nonce",
                "{}", "{}", WalletTransaction.Flow.CROSS_DEVICE, status, null, null, null, now, now.plusSeconds(300));
    }

    @Test
    void requestObject_anyFailureAfterTheClaim_failsTheTransaction_andAnswersASpecError() {
        final SigningKeyHandle broken = mock(SigningKeyHandle.class);
        when(broken.certificateChain()).thenThrow(new IllegalArgumentException("KMS unreachable"));
        when(provider.signingKey()).thenReturn(broken);
        when(store.claimRequest("rid")).thenReturn(Optional.of(tx(WalletTransaction.Status.REQUEST_FETCHED, "b")));
        final OpenId4VpVerifierController controller = new OpenId4VpVerifierController(registry,
                mock(WalletResponseHandler.class), "https://helix.example");

        final ResponseEntity<?> response = controller.requestObject(ALIAS, "rid",
                new MockHttpServletRequest("GET", "/realms/acme/oid4vp/eudi-wallet/request/rid"));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).isEqualTo("{\"error\":\"invalid_request\"}");
        verify(store).fail("tx-1", WalletErrorCode.INVALID_RESPONSE);
    }

    private ResponseEntity<Map<String, Object>> status(final WalletTransaction.Status status) {
        final MockHttpSession session = new MockHttpSession();
        final String binding = BrowserBinding.begin(session, ALIAS);
        when(store.byTransactionId("tx-1")).thenReturn(Optional.of(tx(status, binding)));
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return new WalletPageController(registry, "https://helix.example").status(ALIAS, "tx-1", request);
    }

    @Test
    void status_showsTheBoundBrowserThatTheWalletOpenedTheRequest() {
        assertThat(status(WalletTransaction.Status.CREATED).getBody()).isEqualTo(Map.of("status", "PENDING"));
        assertThat(status(WalletTransaction.Status.REQUEST_FETCHED).getBody())
                .isEqualTo(Map.of("status", "WALLET_OPENED"));
        assertThat(status(WalletTransaction.Status.RESPONSE_RECEIVED).getBody())
                .isEqualTo(Map.of("status", "WALLET_OPENED"));
        assertThat(status(WalletTransaction.Status.FAILED).getBody()).isEqualTo(Map.of("status", "FAILED"));
    }

    @Test
    void status_aStoredExpiredStatus_isA404LikeAnyExpiredTransaction() {
        final ResponseEntity<Map<String, Object>> expired = status(WalletTransaction.Status.EXPIRED);

        assertThat(expired.getStatusCode().value()).isEqualTo(404);
        assertThat(expired.getBody()).isEmpty();
    }
}
