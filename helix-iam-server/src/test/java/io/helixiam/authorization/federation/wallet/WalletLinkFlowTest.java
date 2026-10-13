/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.flow.BrowserBinding;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Task 21b: the account console's wallet link flow. {@code start} opens a LINK transaction of the signed-in user, bound
 * to this browser; {@code complete} redeems it only with this browser's state and binding, only for the same user, and
 * then links the resolved subject: the number (and the tuple when the provider accepts it), or the tuple. It never signs
 * anyone in. The link store is a mock; the transaction store and provider are real.
 */
class WalletLinkFlowTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String USER = "user-7";
    private static final TestPki.Leaf ACCESS = TestPki.create("Link Access").issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestPki ISSUERS = TestPki.create("Link PID Provider");

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100);
    private final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
    private final WalletLinkService links = mock(WalletLinkService.class);
    private final WalletLinkedNotice notice = mock(WalletLinkedNotice.class);
    private final WalletLinkFlow flow = new WalletLinkFlow(links, notice);
    private final MockHttpSession session = new MockHttpSession();

    private WalletIdentityProvider provider() {
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", ISSUERS.rootPem());
        return new WalletIdentityProviders(new WalletConfigValidator(keys, DeploymentProfile.production()), keys,
                store, new OutboundUrlGuard(), mock(AuditLog.class))
                .build(REALM, WalletProviderConfig.fromStored(ALIAS, "EU Digital Identity Wallet", config));
    }

    /** Starts a link in {@link #session} and plays the wallet: the response endpoint stored {@code subject}. */
    private String verified(final WalletIdentityProvider provider, final WalletSubject subject) {
        final String page = flow.start(provider, REALM, USER, session);
        final String txId = page.substring(page.indexOf("tx=") + 3);
        final WalletTransaction tx = store.byTransactionId(txId).orElseThrow();
        assertThat(store.claimRequest(tx.sameDeviceRequestId())).isPresent();
        assertThat(store.claimResponse(tx.responseId())).isPresent();
        final String code = "code-" + txId;
        assertThat(store.complete(txId, code, VerifiedIdentityJson.writeLink(subject))).isTrue();
        return code;
    }

    @Test
    void start_opensALinkTransactionOfTheUser_boundToThisBrowser() {
        final String page = flow.start(provider(), REALM, USER, session);

        assertThat(page).startsWith("/broker/eudi-wallet/wallet?tx=");
        final WalletTransaction tx = store.byTransactionId(page.substring(page.indexOf("tx=") + 3)).orElseThrow();
        assertThat(tx.purpose()).isEqualTo(WalletTransaction.Purpose.LINK);
        assertThat(tx.initiatingUserId()).isEqualTo(USER);
        assertThat(tx.browserBindingHash()).isEqualTo(BrowserBinding.current(session, REALM, ALIAS));
        assertThat(tx.helixState()).isNotBlank();
    }

    @Test
    void startingAgain_discardsTheEarlierLinkTransaction() {
        final WalletIdentityProvider provider = provider();
        final String first = flow.start(provider, REALM, USER, session);

        flow.start(provider, REALM, USER, session);

        assertThat(store.byTransactionId(first.substring(first.indexOf("tx=") + 3))).isEmpty();
    }

    @Test
    void aNumber_isLinkedToTheUser_withItsTuple_whenTheProviderAcceptsTheTuple() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        final String code = verified(provider, new WalletSubject.AdminNumber("aa11", "bb22"));

        assertThat(flow.complete(provider, REALM, USER, code, session)).isEqualTo(WalletLinkFlow.Outcome.LINKED);

        verify(links).link(REALM, USER, ALIAS, new WalletSubject.AdminNumber("aa11", null));
        verify(links).link(REALM, USER, ALIAS, new WalletSubject.Tuple("bb22"));
        assertThat(BrowserBinding.current(session, REALM, ALIAS)).as("the binding is spent").isNull();
    }

    @Test
    void aNumberAlone_isLinked_andNoTupleIsLinked() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.ALREADY_LINKED);
        final String code = verified(provider, new WalletSubject.AdminNumber("aa11", null));

        assertThat(flow.complete(provider, REALM, USER, code, session))
                .isEqualTo(WalletLinkFlow.Outcome.ALREADY_LINKED);

        verify(links).link(REALM, USER, ALIAS, new WalletSubject.AdminNumber("aa11", null));
        verify(links, never()).link(eq(REALM), eq(USER), eq(ALIAS), any(WalletSubject.Tuple.class));
    }

    @Test
    void aTuple_isLinked() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        final String code = verified(provider, new WalletSubject.Tuple("cc33"));

        assertThat(flow.complete(provider, REALM, USER, code, session)).isEqualTo(WalletLinkFlow.Outcome.LINKED);

        verify(links).link(REALM, USER, ALIAS, new WalletSubject.Tuple("cc33"));
    }

    @Test
    void aNumberLinkedToAnotherUser_isRefused_andTheTupleIsNotLinkedEither() {
        final WalletIdentityProvider provider = provider();
        when(links.link(REALM, USER, ALIAS, new WalletSubject.AdminNumber("aa11", null)))
                .thenReturn(WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        final String code = verified(provider, new WalletSubject.AdminNumber("aa11", "bb22"));

        assertThat(flow.complete(provider, REALM, USER, code, session))
                .isEqualTo(WalletLinkFlow.Outcome.LINKED_TO_ANOTHER_USER);

        verify(links, never()).link(eq(REALM), eq(USER), eq(ALIAS), any(WalletSubject.Tuple.class));
    }

    @Test
    void aTupleLinkedToAnotherUser_isRefused() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        final String code = verified(provider, new WalletSubject.Tuple("cc33"));

        assertThat(flow.complete(provider, REALM, USER, code, session))
                .isEqualTo(WalletLinkFlow.Outcome.LINKED_TO_ANOTHER_USER);
    }

    @Test
    void noNumber_andTheFlagOff_isRefusedWithItsReason_andNothingIsLinked() {
        final WalletIdentityProvider provider = provider();
        final String code = verified(provider,
                new WalletSubject.Unavailable(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));

        assertThat(flow.complete(provider, REALM, USER, code, session))
                .isEqualTo(WalletLinkFlow.Outcome.WEAK_SUBJECT_NOT_ACKNOWLEDGED);
        verifyNoInteractions(links);
    }

    @Test
    void missingIdentityAttributes_isRefusedWithItsReason() {
        final WalletIdentityProvider provider = provider();
        final String code = verified(provider,
                new WalletSubject.Unavailable(WalletSubject.Reason.MISSING_IDENTITY_ATTRIBUTES));

        assertThat(flow.complete(provider, REALM, USER, code, session))
                .isEqualTo(WalletLinkFlow.Outcome.MISSING_IDENTITY_ATTRIBUTES);
        verifyNoInteractions(links);
    }

    /** Ruling 2: the session user must be the user that started the link, even in the same browser. */
    @Test
    void anotherUserSignedInToTheSameBrowser_isRefused_andNothingIsLinked() {
        final WalletIdentityProvider provider = provider();
        final String code = verified(provider, new WalletSubject.Tuple("cc33"));

        assertThat(flow.complete(provider, REALM, "user-8", code, session)).isEqualTo(WalletLinkFlow.Outcome.REFUSED);
        verifyNoInteractions(links);
    }

    @Test
    void anotherBrowser_withTheCode_isRefused_andTheCodeStillWorksForTheRightOne() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        final String code = verified(provider, new WalletSubject.Tuple("cc33"));

        assertThat(flow.complete(provider, REALM, USER, code, new MockHttpSession()))
                .isEqualTo(WalletLinkFlow.Outcome.REFUSED);
        assertThat(flow.complete(provider, REALM, USER, code, null)).isEqualTo(WalletLinkFlow.Outcome.REFUSED);
        verifyNoInteractions(links);

        assertThat(flow.complete(provider, REALM, USER, code, session)).isEqualTo(WalletLinkFlow.Outcome.LINKED);
    }

    @Test
    void aCodeIsSingleUse() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        final String code = verified(provider, new WalletSubject.Tuple("cc33"));
        assertThat(flow.complete(provider, REALM, USER, code, session)).isEqualTo(WalletLinkFlow.Outcome.LINKED);

        assertThat(flow.complete(provider, REALM, USER, code, session)).isEqualTo(WalletLinkFlow.Outcome.REFUSED);
    }

    @Test
    void aLoginTransactionsCode_isNeverALink() {
        final WalletIdentityProvider provider = provider();
        final String binding = BrowserBinding.begin(session, REALM, ALIAS);
        final var redirect = provider.start(new io.helixiam.authorization.federation.spi.IdentityProvider
                .AuthnRequestContext(REALM, "login-state", null, binding));
        final String txId = redirect.location().substring(redirect.location().indexOf("tx=") + 3);
        final WalletTransaction tx = store.byTransactionId(txId).orElseThrow();
        store.claimRequest(tx.sameDeviceRequestId());
        store.claimResponse(tx.responseId());
        store.complete(txId, "login-code", VerifiedIdentityJson.writeLink(new WalletSubject.Tuple("cc33")));

        assertThat(flow.complete(provider, REALM, USER, "login-code", session))
                .isEqualTo(WalletLinkFlow.Outcome.REFUSED);
        verifyNoInteractions(links);
    }

    @Test
    void aBlankCode_isRefused() {
        assertThat(flow.complete(provider(), REALM, USER, " ", session)).isEqualTo(WalletLinkFlow.Outcome.REFUSED);
        assertThat(flow.complete(provider(), REALM, USER, null, session)).isEqualTo(WalletLinkFlow.Outcome.REFUSED);
    }

    // ---- production readiness item 4: the "wallet linked" security notice ----

    @Test
    void aNewLink_emailsTheWalletLinkedNotice_once() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        final String code = verified(provider, new WalletSubject.AdminNumber("aa11", "bb22")); // number + tuple

        flow.complete(provider, REALM, USER, code, session);

        verify(notice).send(REALM, USER);
    }

    @Test
    void anExistingLink_aRefusalOrAnotherUsersWallet_sendNoNotice() {
        final WalletIdentityProvider provider = provider();
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.ALREADY_LINKED);
        flow.complete(provider, REALM, USER, verified(provider, new WalletSubject.Tuple("cc33")), session);
        when(links.link(any(), any(), any(), any())).thenReturn(WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        flow.complete(provider, REALM, USER, verified(provider, new WalletSubject.Tuple("dd44")), session);

        verify(notice, never()).send(any(), any());
    }
}
