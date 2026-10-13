/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.security.flow;

import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.FederatedLoginCompleter;
import io.helixiam.authorization.federation.IdentityBroker;
import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.federation.wallet.VerifiedIdentityJson;
import io.helixiam.authorization.federation.wallet.WalletConfigValidator;
import io.helixiam.authorization.federation.wallet.WalletIdentityProvider;
import io.helixiam.authorization.federation.wallet.WalletIdentityProviders;
import io.helixiam.authorization.federation.wallet.WalletLinkService;
import io.helixiam.authorization.federation.wallet.WalletLoginCompleter;
import io.helixiam.authorization.federation.wallet.WalletProviderConfig;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.ui.ConcurrentModel;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Task 18 fix round 1: the broker's wallet branch. One browser holds at most one live wallet login per provider
 * (starting again discards the previous transaction), so one session can never fill the transaction store; and any
 * failure while completing a redeemed wallet login ends at {@code error=federation}, never at an error page.
 */
class FederationBrokerWalletTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final TestPki ACCESS_PKI = TestPki.create("Broker Access");
    private static final TestPki ISSUERS = TestPki.create("Broker PID");

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 2, null);
    private final IdentityProviderRegistry registry = mock(IdentityProviderRegistry.class);
    private final WalletLoginCompleter walletCompleter = mock(WalletLoginCompleter.class);
    private final FederationBrokerController controller = new FederationBrokerController(registry,
            mock(IdentityBroker.class), AccountLinkingPolicy.defaults(), mock(FederatedLoginCompleter.class),
            "https://helix.example", () -> "helix-state");
    private WalletIdentityProvider provider;

    @BeforeEach
    void setUp() {
        RealmContextHolder.set(REALM);
        final TestAccessKeys keys = new TestAccessKeys(ACCESS_PKI.issueLeaf(TestPki.LeafSpec.defaults()), "access",
                REALM);
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", ISSUERS.rootPem());
        provider = new WalletIdentityProviders(new WalletConfigValidator(keys, DeploymentProfile.production()), keys,
                store, new OutboundUrlGuard(), mock(AuditLog.class))
                .build(REALM, WalletProviderConfig.fromStored(ALIAS, "Wallet", config));
        when(registry.get(any(), eq(ALIAS))).thenReturn(provider);
        controller.setWalletLoginCompleter(walletCompleter);
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    private String start(final MockHttpSession session) {
        final MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(session);
        return controller.start(ALIAS, request, new ConcurrentModel());
    }

    private static String txOf(final String view) {
        return view.substring(view.indexOf("tx=") + 3);
    }

    @Test
    void oneSessionStartingOverAndOver_keepsOneLiveTransaction_andNeverReachesTheCap() {
        final MockHttpSession session = new MockHttpSession();
        String previous = null;
        for (int i = 0; i < 10; i++) {
            final String view = start(session);
            assertThat(view).as("start %d", i).startsWith("redirect:/broker/" + ALIAS + "/wallet?tx=");
            if (previous != null) {
                assertThat(store.byTransactionId(previous)).as("the previous login is discarded").isEmpty();
            }
            previous = txOf(view);
        }
        assertThat(store.byTransactionId(previous)).isPresent();

        // Other browsers still get in (the store holds 2): the session above uses one slot, not ten.
        assertThat(start(new MockHttpSession())).contains("/wallet?tx=");
        assertThat(start(new MockHttpSession())).as("the cap itself still applies across sessions")
                .isEqualTo("redirect:/broker/" + ALIAS + "/wallet/unavailable");
    }

    @Test
    void aFailureWhileCompletingARedeemedWalletLogin_endsAtTheFederationError() {
        final MockHttpSession session = new MockHttpSession();
        final String txId = txOf(start(session));
        final WalletTransaction tx = store.byTransactionId(txId).orElseThrow();
        store.claimRequest(tx.crossDeviceRequestId());
        store.claimResponse(tx.responseId());
        store.complete(txId, null, VerifiedIdentityJson.write(new BrokeredIdentity(ALIAS, "s".repeat(64), null, false,
                Map.of(), "http://eidas.europa.eu/LoA/high"), new WalletLinkService.Decision.Existing("user-1")));
        final String code = store.issueResponseCode(txId, BrowserBinding.current(session, REALM, ALIAS)).orElseThrow();
        when(walletCompleter.complete(any(), any(), any(), any(), any()))
                .thenThrow(new IllegalStateException("link store down"));
        final MockHttpServletRequest callback = new MockHttpServletRequest();
        callback.setSession(session);
        callback.setParameter("response_code", code);

        final String view = controller.callback(ALIAS, callback, new MockHttpServletResponse());

        assertThat(view).isEqualTo("redirect:/login?error=federation");
    }
}
