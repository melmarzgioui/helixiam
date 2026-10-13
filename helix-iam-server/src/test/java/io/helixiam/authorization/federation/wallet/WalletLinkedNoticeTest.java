/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.messaging.DefaultMessageTemplates;
import io.helixiam.authorization.messaging.MessagingService;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.service.messaging.MessagingAdminService;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Production readiness item 4: the "wallet linked" security notice. It goes to the account's email address through the
 * realm's email provider and its {@code wallet-linked-notice} template; it carries the realm and nothing about the
 * wallet (no subject hash, no PID value); without an email address on file nothing is sent.
 */
class WalletLinkedNoticeTest {

    private final UserCredentialsRepository users = mock(UserCredentialsRepository.class);
    private final MessagingService messaging = mock(MessagingService.class);
    private final MessagingAdminService templates = mock(MessagingAdminService.class);
    private final WalletLinkedNotice notice = new WalletLinkedNotice(users, messaging, templates);

    private static UserCredentials user(final String realm, final String email) {
        final UserCredentials user = new UserCredentials();
        user.setUserId("user-7");
        user.setRealmId(realm);
        user.setEmail(email);
        return user;
    }

    @Test
    void aLinkedWallet_emailsTheAccountsAddress_withTheRealmOnly() {
        when(users.findByUserId("user-7")).thenReturn(Optional.of(user("acme", "erika@example.org")));
        when(messaging.sendEmail(anyString(), anyString(), anyString(), anyMap())).thenReturn(true);

        notice.send("acme", "user-7");

        verify(templates).ensureDefaultTemplate("acme", WalletLinkedNotice.TEMPLATE);
        verify(messaging).sendEmail("acme", "erika@example.org", WalletLinkedNotice.TEMPLATE, Map.of("realm", "acme"));
    }

    @Test
    void noEmailAddressOnFile_sendsNothing() {
        when(users.findByUserId("user-7")).thenReturn(Optional.of(user("acme", null)));
        notice.send("acme", "user-7");
        when(users.findByUserId("user-7")).thenReturn(Optional.of(user("acme", "  ")));
        notice.send("acme", "user-7");
        when(users.findByUserId("user-7")).thenReturn(Optional.empty());
        notice.send("acme", "user-7");

        verify(messaging, never()).sendEmail(anyString(), anyString(), anyString(), anyMap());
    }

    @Test
    void aUserOfAnotherRealm_isNeverEmailed() {
        when(users.findByUserId("user-7")).thenReturn(Optional.of(user("other", "erika@example.org")));

        notice.send("acme", "user-7");

        verify(messaging, never()).sendEmail(anyString(), anyString(), anyString(), anyMap());
    }

    @Test
    void aFailingProvider_neverFailsTheLink() {
        when(users.findByUserId("user-7")).thenReturn(Optional.of(user("acme", "erika@example.org")));
        when(messaging.sendEmail(anyString(), anyString(), anyString(), anyMap()))
                .thenThrow(new IllegalStateException("smtp down"));

        notice.send("acme", "user-7"); // no exception
        verify(templates).ensureDefaultTemplate(any(), any());
    }

    @Test
    void theDefaultTemplates_sayWhatHappenedAndWhatToDo_andCarryNoWalletOrUserData() {
        final DefaultMessageTemplates.Template english = DefaultMessageTemplates.english().stream()
                .filter(t -> t.key().equals(WalletLinkedNotice.TEMPLATE)).findFirst().orElseThrow();
        assertThat(english.channel()).isEqualTo("EMAIL");
        assertThat(english.subject() + " " + english.body())
                .contains("An EU Digital Identity Wallet was linked to your")
                .contains("If this wasn't you, unlink it and change your password.");
        final DefaultMessageTemplates.Template dutch = DefaultMessageTemplates.dutch(WalletLinkedNotice.TEMPLATE)
                .orElseThrow();
        for (final DefaultMessageTemplates.Template t : java.util.List.of(english, dutch)) {
            // The only placeholder is the realm: nothing from the wallet (subject hash, PID) or the user's profile.
            assertThat((t.subject() + t.body()).replace("{{realm}}", "")).doesNotContain("{{");
        }
    }
}
