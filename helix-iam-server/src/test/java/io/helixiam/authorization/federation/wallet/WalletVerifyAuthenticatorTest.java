/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.federation.IdentityProviderRegistry;
import io.helixiam.authorization.federation.wallet.testwallet.TestAccessKeys;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.transaction.InMemoryWalletTransactionStore;
import io.helixiam.authorization.federation.wallet.transaction.WalletTransaction;
import io.helixiam.authorization.flow.spi.AuthenticationContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
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
 * The verify-only wallet flow step: it never runs without an identified user, starts a VERIFY transaction of a
 * verify-only connection only, and binds the redeemed wallet to the user (design D4: the number wins, then the tuple,
 * never an unlinked wallet). The wallet half is simulated on the in-memory store.
 */
class WalletVerifyAuthenticatorTest {

    private static final String REALM = "acme";
    private static final String VERIFY_ALIAS = "eudi-verify";
    private static final String LOGIN_ALIAS = "eudi-wallet";
    private static final String LOA = "http://eidas.europa.eu/LoA/high";
    private static final TestPki.Leaf ACCESS = TestPki.create("Verify Access").issueLeaf(TestPki.LeafSpec.defaults());
    private static final TestPki ISSUERS = TestPki.create("Verify PID Provider");

    private final InMemoryWalletTransactionStore store = new InMemoryWalletTransactionStore(Clock.systemUTC(), 100);
    private final TestAccessKeys keys = new TestAccessKeys(ACCESS, "eudi-access", REALM);
    private final WalletLinkService links = mock(WalletLinkService.class);
    private final AuditLog audit = mock(AuditLog.class);
    private final IdentityProviderRegistry registry = new IdentityProviderRegistry(List.of());
    private final WalletVerifyAuthenticator step = new WalletVerifyAuthenticator(registry, links, audit);

    @BeforeEach
    void setUp() {
        registry.reload(REALM, List.of(provider(VERIFY_ALIAS, true), provider(LOGIN_ALIAS, false)));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }

    private WalletIdentityProvider provider(final String alias, final boolean verifyOnly) {
        final Map<String, String> config = new HashMap<>();
        config.put("accessKeyRef", keys.ref(REALM));
        config.put("trustAnchors", ISSUERS.rootPem());
        if (verifyOnly) {
            config.put("subject.strategy", "NONE");
            config.put("verify.linkedProvider", LOGIN_ALIAS);
            config.put("pid.requestedClaims", "[\"birthdate\"]");
            config.put("verify.releasedClaims", "[\"age_over_18\"]");
        }
        return new WalletIdentityProviders(new WalletConfigValidator(keys, DeploymentProfile.production()), keys,
                store, new OutboundUrlGuard(), mock(AuditLog.class))
                .build(REALM, WalletProviderConfig.fromStored(alias, alias, config));
    }

    private static AuthenticationContext context(final String userId, final String alias) {
        return new AuthenticationContext("e-wallet", REALM, userId, Map.of(WalletVerifyAuthenticator.PROVIDER_ALIAS,
                alias));
    }

    /** Starts the step for user-7 and lets the "wallet" answer with {@code subject}; returns the callback context. */
    private AuthenticationContext answered(final WalletSubject subject) {
        final AuthenticationContext started = context("user-7", VERIFY_ALIAS);
        step.authenticate(started);
        assertThat(started.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        final String txId = (String) started.getAttribute(WalletVerifyAuthenticator.TX_ATTRIBUTE);
        final WalletTransaction tx = store.byTransactionId(txId).orElseThrow();
        assertThat(store.claimRequest(tx.sameDeviceRequestId())).isPresent();
        assertThat(store.claimResponse(tx.responseId())).isPresent();
        final Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("age_over_18", true);
        assertThat(store.complete(txId, "code-" + txId, VerifiedIdentityJson.writeVerify(subject, claims, LOA,
                "dc+sd-jwt", "CN=PID"))).isTrue();
        final AuthenticationContext callback = context("user-7", VERIFY_ALIAS);
        callback.attributes().putAll(started.attributes());
        callback.submit(Map.of("response_code", "code-" + txId));
        return callback;
    }

    private AuditEvent lastAudit() {
        final ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit, atLeastOnce()).emit(events.capture());
        return events.getValue();
    }

    @Test
    void withoutAnIdentifiedUser_theStepFails_itIsNeverAFirstFactor() {
        final AuthenticationContext context = context(null, VERIFY_ALIAS);
        step.authenticate(context);
        assertThat(context.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void aLoginConnection_cannotBeUsedForTheStep() {
        final AuthenticationContext context = context("user-7", LOGIN_ALIAS);
        step.authenticate(context);
        assertThat(context.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        final AuthenticationContext unknown = context("user-7", "nope");
        step.authenticate(unknown);
        assertThat(unknown.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void theStep_startsAVerifyTransactionOfTheUser_andSendsTheBrowserToTheWalletPage() {
        final AuthenticationContext context = context("user-7", VERIFY_ALIAS);
        step.authenticate(context);

        assertThat(context.challengeView()).isEqualTo(WalletVerifyAuthenticator.VIEW);
        assertThat((String) context.getAttribute(AuthenticationContext.REDIRECT_ATTRIBUTE))
                .startsWith("/broker/eudi-verify/wallet?tx=");
        final WalletTransaction tx = store.byTransactionId(
                (String) context.getAttribute(WalletVerifyAuthenticator.TX_ATTRIBUTE)).orElseThrow();
        assertThat(tx.purpose()).isEqualTo(WalletTransaction.Purpose.VERIFY);
        assertThat(tx.initiatingUserId()).isEqualTo("user-7");
    }

    @Test
    void theUsersOwnNumber_succeeds_assertsTheLoa_andAuditsWithoutReleasingOutsideAnAuthorizationRequest() {
        when(links.find(REALM, LOGIN_ALIAS, new WalletSubject.AdminNumber("n1", null))).thenReturn(Optional.of("user-7"));
        final AuthenticationContext callback = answered(new WalletSubject.AdminNumber("n1", null));

        step.action(callback);

        assertThat(callback.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
        assertThat(callback.assertedLevelOfAssurance()).isEqualTo(LOA);
        assertThat(callback.releasedVerifiedClaims()).as("no authorization request is pending").isNull();
        assertThat(lastAudit().type()).isEqualTo(WalletVerifyAudit.SUCCESS_TYPE);
        assertThat(lastAudit().actor()).isEqualTo("user-7");
    }

    @Test
    void someoneElsesNumber_isABindingMismatch_evenWhenTheTupleIsTheUsers() {
        when(links.find(REALM, LOGIN_ALIAS, new WalletSubject.AdminNumber("n1", null))).thenReturn(Optional.of("mallory"));
        when(links.find(REALM, LOGIN_ALIAS, new WalletSubject.Tuple("t1"))).thenReturn(Optional.of("user-7"));
        final AuthenticationContext callback = answered(new WalletSubject.AdminNumber("n1", "t1"));

        step.action(callback);

        assertThat(callback.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(callback.assertedLevelOfAssurance()).isNull();
        assertThat(lastAudit().type()).isEqualTo(WalletVerifyAudit.FAILURE_TYPE);
        assertThat(lastAudit().detail()).containsEntry("reason", "BINDING_MISMATCH");
    }

    @Test
    void anUnlinkedNumber_withTheUsersTuple_succeeds_asTheLoginWouldSignInAsThem() {
        when(links.find(any(), any(), any())).thenReturn(Optional.empty());
        when(links.find(REALM, LOGIN_ALIAS, new WalletSubject.Tuple("t1"))).thenReturn(Optional.of("user-7"));
        final AuthenticationContext callback = answered(new WalletSubject.AdminNumber("n1", "t1"));

        step.action(callback);

        assertThat(callback.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);
    }

    @Test
    void anUnlinkedWallet_isRefused() {
        when(links.find(any(), any(), any())).thenReturn(Optional.empty());
        final AuthenticationContext callback = answered(new WalletSubject.AdminNumber("n1", null));

        step.action(callback);

        assertThat(callback.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(lastAudit().detail()).containsEntry("reason", "SUBJECT_UNAVAILABLE");
    }

    @Test
    void anotherUsersVerification_isRefused() {
        when(links.find(any(), any(), any())).thenReturn(Optional.of("user-7"));
        final AuthenticationContext callback = answered(new WalletSubject.AdminNumber("n1", null));
        final AuthenticationContext other = new AuthenticationContext("e-wallet", REALM, "mallory",
                Map.of(WalletVerifyAuthenticator.PROVIDER_ALIAS, VERIFY_ALIAS));
        other.attributes().putAll(callback.attributes());
        other.submit(Map.of("response_code", callback.formParameter("response_code")));

        step.action(other);

        assertThat(other.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
        assertThat(lastAudit().detail()).containsEntry("reason", "BINDING_MISMATCH");
    }

    @Test
    void aWrongOrReusedCode_isRefused() {
        when(links.find(any(), any(), any())).thenReturn(Optional.of("user-7"));
        final AuthenticationContext callback = answered(new WalletSubject.AdminNumber("n1", null));
        step.action(callback);
        assertThat(callback.status()).isEqualTo(AuthenticationContext.Status.SUCCESS);

        final AuthenticationContext replay = context("user-7", VERIFY_ALIAS);
        replay.attributes().putAll(callback.attributes());
        replay.submit(Map.of("response_code", callback.formParameter("response_code")));
        step.action(replay);
        assertThat(replay.status()).isEqualTo(AuthenticationContext.Status.FAILURE);
    }

    @Test
    void restart_startsANewVerification_andAnEmptySubmitReChallenges() {
        final AuthenticationContext started = context("user-7", VERIFY_ALIAS);
        step.authenticate(started);
        final String first = (String) started.getAttribute(WalletVerifyAuthenticator.TX_ATTRIBUTE);

        final AuthenticationContext again = context("user-7", VERIFY_ALIAS);
        again.attributes().putAll(started.attributes());
        again.submit(Map.of(WalletVerifyAuthenticator.RESTART_PARAM, "1"));
        step.action(again);
        assertThat(again.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
        assertThat(again.getAttribute(WalletVerifyAuthenticator.TX_ATTRIBUTE)).isNotEqualTo(first);
        assertThat(store.byTransactionId(first)).as("the earlier one is discarded").isEmpty();

        final AuthenticationContext empty = context("user-7", VERIFY_ALIAS);
        empty.submit(Map.of());
        step.action(empty);
        assertThat(empty.status()).isEqualTo(AuthenticationContext.Status.CHALLENGE);
    }
}
