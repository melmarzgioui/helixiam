/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service;

import io.helixiam.authorization.domain.user.UserCredentials;
import io.helixiam.authorization.repository.ChangePasswordRepository;
import io.helixiam.authorization.repository.MfaUserRepository;
import io.helixiam.authorization.repository.UserCredentialsRepository;
import io.helixiam.authorization.repository.VerifyEmailRepository;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.notification.NotificationCodeIssuer;
import io.helixiam.notification.NotificationCodePolicy;
import io.helixiam.notification.Notifier;
import io.helixiam.notification.domain.NotificationRequest;
import io.helixiam.notification.repository.NotificationCodeRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Security: the password-reset link goes only to the account's stored email address. The typed value only finds the
 * account (username or email, in the realm); an unknown account, or one without an address, gets no email, and the
 * caller cannot tell the cases apart.
 */
class PasswordResetRequestTest {

    private final UserCredentialsRepository users = mock(UserCredentialsRepository.class);
    private final NotificationCodeRepository codes = mock(NotificationCodeRepository.class);
    private final Notifier notifier = mock(Notifier.class);
    private UserService service;

    @BeforeEach
    void setUp() {
        RealmContextHolder.set("acme");
        when(users.findByRealmIdAndUsername(anyString(), anyString())).thenReturn(Optional.empty());
        when(users.findByRealmIdAndEmail(anyString(), anyString())).thenReturn(Optional.empty());
        when(codes.findByIdentifierAndType(anyString(), anyString())).thenReturn(Optional.empty());
        service = new UserService(users, mock(ChangePasswordRepository.class), codes, mock(VerifyEmailRepository.class),
                mock(MfaUserRepository.class), notifier, new PasswordEncoderService());
        // Runs the mail task inline, so the test sees it.
        service.setPasswordResetMailer(new PasswordResetMailer(new NotificationCodeIssuer(codes,
                NotificationCodePolicy.defaults()), notifier, Runnable::run));
    }

    @AfterEach
    void clear() {
        RealmContextHolder.clear();
    }

    private static UserCredentials account(final String username, final String email) {
        final UserCredentials u = new UserCredentials();
        u.setUserId("u-" + username);
        u.setUsername(username);
        u.setEmail(email);
        return u;
    }

    private NotificationRequest sent() {
        final ArgumentCaptor<NotificationRequest> request = ArgumentCaptor.forClass(NotificationRequest.class);
        verify(notifier).sendEmailNotification(request.capture());
        return request.getValue();
    }

    @Test
    void aTypedUsername_sendsTheLinkToTheStoredEmail() {
        when(users.findByRealmIdAndUsername("acme", "ada")).thenReturn(Optional.of(account("ada", "ada@example.com")));

        service.resetPasswordRequest(" Ada ");

        final NotificationRequest request = sent();
        assertThat(request.getType()).isEqualTo("USER_RESET_PASSWORD");
        assertThat(request.getEmailAddress()).isEqualTo("ada@example.com");
        assertThat(request.getNotificationCode().getCode()).isNotBlank();
        verify(codes).save(any()); // a code is issued (hashed) for the account
    }

    @Test
    void aUsernameThatLooksLikeAnotherAddress_sendsOnlyToTheStoredEmail() {
        when(users.findByRealmIdAndUsername("acme", "old@example.org"))
                .thenReturn(Optional.of(account("old@example.org", "new@example.com")));

        service.resetPasswordRequest("old@example.org");

        assertThat(sent().getEmailAddress()).isEqualTo("new@example.com");
    }

    @Test
    void anUnknownAccount_getsNoEmail_andNoCode() {
        service.resetPasswordRequest("nobody@example.com");

        verify(notifier, never()).sendEmailNotification(any());
        verify(codes, never()).save(any());
    }

    @Test
    void anAccountWithoutAnEmail_getsNoEmail_andNoCode() {
        when(users.findByRealmIdAndUsername("acme", "noemail")).thenReturn(Optional.of(account("noemail", null)));

        service.resetPasswordRequest("noemail");

        verify(notifier, never()).sendEmailNotification(any());
        verify(codes, never()).save(any());
    }

    @Test
    void theEmailIsSentOffTheRequestThread() {
        final java.util.List<Runnable> queued = new java.util.ArrayList<>();
        service.setPasswordResetMailer(new PasswordResetMailer(new NotificationCodeIssuer(codes,
                NotificationCodePolicy.defaults()), notifier, queued::add));
        when(users.findByRealmIdAndUsername("acme", "ada")).thenReturn(Optional.of(account("ada", "ada@example.com")));

        service.resetPasswordRequest("ada");

        verify(notifier, never()).sendEmailNotification(any()); // not on the caller's thread
        verify(codes, never()).save(any());
        assertThat(queued).hasSize(1);
        queued.get(0).run();
        assertThat(sent().getEmailAddress()).isEqualTo("ada@example.com");
        verify(codes).save(any());
    }
}
