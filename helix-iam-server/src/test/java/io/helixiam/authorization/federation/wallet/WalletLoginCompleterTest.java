/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.amqp.user.UserAdminPublisher;
import io.helixiam.authorization.amqp.user.UserAdminRef;
import io.helixiam.authorization.federation.AccountLinkingPolicy;
import io.helixiam.authorization.federation.DefaultAttributeMapper;
import io.helixiam.authorization.federation.FederatedIdentityStore;
import io.helixiam.authorization.federation.FederatedLoginCompleter;
import io.helixiam.authorization.federation.spi.BrokeredIdentity;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Task 18: the wallet-aware end of a wallet login, after the response code was redeemed. It acts on the account
 * decision the response endpoint stored ({@link WalletLinkService#decide}): an existing link signs in (an upgrade link
 * is committed only after the login completed), a new administrative number is provisioned and linked insert-if-absent
 * (a lost race signs in as the winner and removes the fresh account), and a refusal explains how to link the wallet.
 * It never links by email and never overwrites a link.
 */
class WalletLoginCompleterTest {

    private static final String REALM = "acme";
    private static final String ALIAS = "eudi-wallet";
    private static final String SUBJECT = "a".repeat(64);
    private static final String LOA = "http://eidas.europa.eu/LoA/high";

    private final FederatedIdentityStore store = mock(FederatedIdentityStore.class);
    private final WalletLinkService links = mock(WalletLinkService.class);
    private final UserAdminPublisher users = mock(UserAdminPublisher.class);
    private final FederatedLoginCompleter completer = mock(FederatedLoginCompleter.class);
    private final AuditLog audit = mock(AuditLog.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    private WalletLoginCompleter walletCompleter(final AccountLinkingPolicy policy) {
        return new WalletLoginCompleter(store, new DefaultAttributeMapper(), policy, links, users, completer, audit);
    }

    private static BrokeredIdentity identity() {
        return new BrokeredIdentity(ALIAS, SUBJECT, null, false, Map.of("given_name", "Erika",
                "family_name", "Mustermann"), LOA);
    }

    @BeforeEach
    void bindRealm() {
        RealmContextHolder.set(REALM);
    }

    @AfterEach
    void clearRealm() {
        RealmContextHolder.clear();
    }

    @Test
    void existing_signsInAsTheLinkedUser() {
        when(completer.complete("user-7", LOA, request, response, null)).thenReturn("redirect:/done");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Existing("user-7")),
                null, request, response);

        assertThat(view).isEqualTo("redirect:/done");
        verifyNoInteractions(store, users);
        verify(links, never()).link(any(), any(), any(), any());
        // Task 22: a completed login audits WALLET_LOGIN_SUCCESS, actor = the resolved local user id.
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("WALLET_LOGIN_SUCCESS");
        assertThat(event.getValue().realm()).isEqualTo(REALM);
        assertThat(event.getValue().actor()).isEqualTo("user-7");
        assertThat(event.getValue().outcome()).isEqualTo("SUCCESS");
        assertThat(event.getValue().detail()).containsEntry("alias", ALIAS).containsEntry("result", "SUCCESS")
                .doesNotContainKey("transactionId").doesNotContainKey("format").doesNotContainKey("issuerDn")
                .doesNotContainValue("Erika");
    }

    @Test
    void existing_withTransactionFormatAndIssuerDn_carriesThemOnTheSuccessEvent() {
        when(completer.complete("user-7", LOA, request, response, null)).thenReturn("redirect:/done");
        final VerifiedIdentityJson.StoredLogin login = new VerifiedIdentityJson.StoredLogin(identity(),
                new WalletLinkService.Decision.Existing("user-7"), "dc+sd-jwt", "CN=Issuer", null)
                .withTransactionId("tx-9");

        walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS, login, null, request, response);

        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).emit(event.capture());
        assertThat(event.getValue().detail()).containsEntry("transactionId", "tx-9")
                .containsEntry("format", "dc+sd-jwt").containsEntry("issuerDn", "CN=Issuer");
    }

    @Test
    void existingWithAnUpgradeLink_handsThePendingLinkToTheCompleter_neverCommittingItItself() {
        final WalletLinkService.PendingLink pending = new WalletLinkService.PendingLink(REALM, ALIAS, "number", "user-7");
        when(completer.complete("user-7", LOA, request, response, pending)).thenReturn("redirect:/flow");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Existing("user-7",
                        pending)), null, request, response);

        assertThat(view).isEqualTo("redirect:/flow");
        verify(links, never()).commitPendingLink(any());
        // a pending step-up is not yet a completed login: no success audit yet
        verifyNoInteractions(audit);
    }

    @Test
    void provision_createsTheUserWithoutEmail_thenLinksTheNumberInsertIfAbsent() {
        when(store.provisionUser(any(), any())).thenReturn("new-user");
        when(links.link(eq(REALM), eq("new-user"), eq(ALIAS), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        when(completer.complete("new-user", LOA, request, response, null)).thenReturn("redirect:/done");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Provision()),
                "given_name=firstName", request, response);

        assertThat(view).isEqualTo("redirect:/done");
        @SuppressWarnings("unchecked")
        final ArgumentCaptor<Map<String, String>> attributes = ArgumentCaptor.forClass(Map.class);
        verify(store).provisionUser(eq(identity()), attributes.capture());
        assertThat(attributes.getValue()).containsEntry("username", SUBJECT).containsEntry("firstName", "Erika")
                .doesNotContainKey("email");
        final ArgumentCaptor<WalletSubject> subject = ArgumentCaptor.forClass(WalletSubject.class);
        verify(links).link(eq(REALM), eq("new-user"), eq(ALIAS), subject.capture());
        assertThat(subject.getValue()).isEqualTo(new WalletSubject.AdminNumber(SUBJECT, null));
        // never the overwriting link, never an email lookup
        verify(store, never()).link(anyString(), anyString(), anyString());
        verify(store, never()).findUserByEmail(anyString());
    }

    /** JIT race: another login linked the number first; sign in as that owner and leave no orphan account. */
    @Test
    void provision_losingTheLinkRace_signsInAsTheWinner_andDeletesTheFreshUser() {
        when(store.provisionUser(any(), any())).thenReturn("loser");
        when(links.link(eq(REALM), eq("loser"), eq(ALIAS), any()))
                .thenReturn(WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        when(links.find(eq(REALM), eq(ALIAS), any())).thenReturn(Optional.of("winner"));
        when(completer.complete("winner", LOA, request, response, null)).thenReturn("redirect:/done");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Provision()),
                null, request, response);

        assertThat(view).isEqualTo("redirect:/done");
        verify(users).delete(new UserAdminRef(REALM, "loser"));
        // the removal is audited like an admin user deletion, with the reason, AND the winner's login succeeded
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit, org.mockito.Mockito.times(2)).emit(event.capture());
        final AuditEvent delete = event.getAllValues().stream().filter(e -> "USER_DELETE".equals(e.type()))
                .findFirst().orElseThrow();
        assertThat(delete.realm()).isEqualTo(REALM);
        assertThat(delete.resourceType()).isEqualTo("user");
        assertThat(delete.resourceId()).isEqualTo("loser");
        assertThat(delete.detail()).containsEntry("reason", "wallet_jit_race_lost").doesNotContainValue("Erika");
        final AuditEvent success = event.getAllValues().stream().filter(e -> "WALLET_LOGIN_SUCCESS".equals(e.type()))
                .findFirst().orElseThrow();
        assertThat(success.actor()).isEqualTo("winner");
        assertThat(success.detail()).containsEntry("alias", ALIAS).containsEntry("result", "SUCCESS");
    }

    /** JIT race, other shape: the default username (the subject) is unique per realm, so the second insert fails. */
    @Test
    void provision_whoseInsertFailsBecauseAConcurrentLoginProvisionedFirst_signsInAsThatAccount() {
        when(store.provisionUser(any(), any())).thenThrow(new org.springframework.dao.DataIntegrityViolationException(
                "duplicate username"));
        when(links.find(eq(REALM), eq(ALIAS), any())).thenReturn(Optional.of("winner"));
        when(completer.complete("winner", LOA, request, response, null)).thenReturn("redirect:/done");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Provision()),
                null, request, response);

        assertThat(view).isEqualTo("redirect:/done");
        verify(links, never()).link(any(), any(), any(), any());
        verifyNoInteractions(users);
    }

    @Test
    void provision_anUnexpectedFailure_propagates_andIsNotTakenForARace() {
        when(store.provisionUser(any(), any())).thenThrow(new IllegalStateException("database down"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> walletCompleter(AccountLinkingPolicy.defaults())
                .complete(ALIAS, new VerifiedIdentityJson.StoredLogin(identity(),
                        new WalletLinkService.Decision.Provision()), null, request, response))
                .isInstanceOf(IllegalStateException.class);
        verify(links, never()).find(any(), any(), any());
        verifyNoInteractions(completer, users);
    }

    /**
     * A stale user (no link) holds the default username, the subject: provisioning retries ONCE with a suffixed
     * username and links the new account; the stale user is left alone.
     */
    @Test
    void provision_staleUserHoldingTheUsername_retriesOnceWithASuffixedUsername() {
        when(store.provisionUser(any(), any()))
                .thenThrow(new org.springframework.dao.DataIntegrityViolationException("duplicate username"))
                .thenReturn("new-user");
        when(links.find(eq(REALM), eq(ALIAS), any())).thenReturn(Optional.empty());
        when(links.link(eq(REALM), eq("new-user"), eq(ALIAS), any())).thenReturn(WalletLinkService.LinkResult.LINKED);
        when(completer.complete("new-user", LOA, request, response, null)).thenReturn("redirect:/done");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Provision()),
                null, request, response);

        assertThat(view).isEqualTo("redirect:/done");
        @SuppressWarnings("unchecked")
        final ArgumentCaptor<Map<String, String>> attributes = ArgumentCaptor.forClass(Map.class);
        verify(store, org.mockito.Mockito.times(2)).provisionUser(any(), attributes.capture());
        assertThat(attributes.getAllValues().get(0)).containsEntry("username", SUBJECT);
        assertThat(attributes.getAllValues().get(1).get("username")).startsWith(SUBJECT + "-")
                .hasSize(SUBJECT.length() + 1 + 16);
    }

    @Test
    void provision_aDuplicateOnTheRetryToo_givesUpWithoutLooping() {
        when(store.provisionUser(any(), any()))
                .thenThrow(new org.springframework.dao.DataIntegrityViolationException("duplicate username"));
        when(links.find(eq(REALM), eq(ALIAS), any())).thenReturn(Optional.empty());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> walletCompleter(AccountLinkingPolicy.defaults())
                .complete(ALIAS, new VerifiedIdentityJson.StoredLogin(identity(),
                        new WalletLinkService.Decision.Provision()), null, request, response))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        verify(store, org.mockito.Mockito.times(2)).provisionUser(any(), any());
        verifyNoInteractions(completer, users);
    }

    @Test
    void provision_isRefused_whenTheRealmDoesNotProvision() {
        final VerifiedIdentityJson.StoredLogin login = new VerifiedIdentityJson.StoredLogin(identity(),
                new WalletLinkService.Decision.Provision()).withTransactionId("tx-1");

        final String view = walletCompleter(new AccountLinkingPolicy(true, false)).complete(ALIAS, login, null,
                request, response);

        assertThat(view).isEqualTo("redirect:/broker/" + ALIAS + "/wallet/link?reason=link_required");
        verifyNoInteractions(store, users, completer);
        // Task 22 fix round 1: a presentation that was verified but can never create an account is still a FAILED
        // login, not a silent non-event.
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("WALLET_LOGIN_FAILURE");
        assertThat(event.getValue().detail()).containsEntry("reason", "SUBJECT_UNAVAILABLE")
                .containsEntry("transactionId", "tx-1").containsEntry("alias", ALIAS);
    }

    @Test
    void refused_sendsTheUserToTheLinkExplanation() {
        final VerifiedIdentityJson.StoredLogin login = new VerifiedIdentityJson.StoredLogin(null,
                new WalletLinkService.Decision.Refused(WalletSubject.Reason.WEAK_SUBJECT_NOT_ACKNOWLEDGED));

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS, login, null, request,
                response);

        assertThat(view).isEqualTo("redirect:/broker/" + ALIAS
                + "/wallet/link?reason=weak_subject_not_acknowledged");
        verifyNoInteractions(store, users, completer);
        // Task 22 fix round 1: same as above — a verified-but-refused presentation audits a failure.
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("WALLET_LOGIN_FAILURE");
        assertThat(event.getValue().detail()).containsEntry("reason", "SUBJECT_UNAVAILABLE");
    }

    /**
     * Task 22 fix round 1 (Critical #1): even the race's loser, when the winner cannot be found either (a bug/race
     * edge case), must end in exactly one audit event.
     */
    @Test
    void provision_losingTheLinkRace_andTheWinnerCannotBeFoundEither_stillAuditsAFailure() {
        when(store.provisionUser(any(), any())).thenReturn("loser");
        when(links.link(eq(REALM), eq("loser"), eq(ALIAS), any()))
                .thenReturn(WalletLinkService.LinkResult.LINKED_TO_ANOTHER_USER);
        when(links.find(eq(REALM), eq(ALIAS), any())).thenReturn(Optional.empty());

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS,
                new VerifiedIdentityJson.StoredLogin(identity(), new WalletLinkService.Decision.Provision()),
                null, request, response);

        assertThat(view).isEqualTo("redirect:/login?error=federation");
        verify(users).delete(new UserAdminRef(REALM, "loser"));
        final ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit, org.mockito.Mockito.times(2)).emit(events.capture());
        assertThat(events.getAllValues().stream().filter(e -> "WALLET_LOGIN_FAILURE".equals(e.type())).findFirst())
                .as("the login itself failed, not just the delete")
                .hasValueSatisfying(e -> assertThat(e.detail()).containsEntry("reason", "INVALID_RESPONSE"));
    }

    /**
     * Task 22 fix round 1 (Critical #1): when the shared {@link FederatedLoginCompleter} itself fails the post-broker
     * flow (its own {@code LOGIN_ERROR_VIEW}, e.g. a pending-commit refused), the wallet login must still audit
     * exactly one failure, not zero.
     */
    @Test
    void existing_whenTheSharedCompleterItselfFails_auditsAFailure_notASuccess() {
        when(completer.complete("user-7", LOA, request, response, null))
                .thenReturn(FederatedLoginCompleter.LOGIN_ERROR_VIEW);
        final VerifiedIdentityJson.StoredLogin login = new VerifiedIdentityJson.StoredLogin(identity(),
                new WalletLinkService.Decision.Existing("user-7")).withTransactionId("tx-9");

        final String view = walletCompleter(AccountLinkingPolicy.defaults()).complete(ALIAS, login, null, request,
                response);

        assertThat(view).isEqualTo(FederatedLoginCompleter.LOGIN_ERROR_VIEW);
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("WALLET_LOGIN_FAILURE");
        assertThat(event.getValue().detail()).containsEntry("reason", "INVALID_RESPONSE")
                .containsEntry("transactionId", "tx-9");
    }

    @Test
    void theCommitter_acceptsOnlyAPendingLinkWhoseOwnerIsTheSignedInUser() {
        final WalletPendingLinkCommit commit = new WalletPendingLinkCommit(links);
        final WalletLinkService.PendingLink pending = new WalletLinkService.PendingLink(REALM, ALIAS, "n", "user-7");

        when(links.commitPendingLink(pending)).thenReturn(Optional.of("user-7"));
        assertThat(commit.commit(pending, "user-7")).isTrue();

        when(links.commitPendingLink(pending)).thenReturn(Optional.of("someone-else"));
        assertThat(commit.commit(pending, "user-7")).as("another user claimed the number first").isFalse();

        when(links.commitPendingLink(pending)).thenReturn(Optional.empty());
        assertThat(commit.commit(pending, "user-7")).isFalse();

        assertThat(commit.commit(pending, "user-8")).as("not this user's link").isFalse();
        assertThat(commit.commit("not a pending link", "user-7")).isFalse();
    }
}
