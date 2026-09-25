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
import io.helixiam.notification.Notifier;
import io.helixiam.notification.domain.NotificationCode;
import io.helixiam.notification.domain.NotificationRequest;
import io.helixiam.notification.repository.NotificationCodeRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Helix IAM: user-claim assembly for OIDC tokens. The {@code email} column and {@code username}
 * are surfaced as claims (mapped downstream to {@code email}/{@code preferred_username}) alongside
 * the free-form profile attributes.
 */
class UserServiceTest {

    private UserCredentialsRepository userCredentialsRepository;
    private NotificationCodeRepository notificationCodeRepository;
    private Notifier notifier;
    private UserService service;

    @BeforeEach
    void setUp() {
        userCredentialsRepository = mock(UserCredentialsRepository.class);
        notificationCodeRepository = mock(NotificationCodeRepository.class);
        notifier = mock(Notifier.class);
        service = new UserService(userCredentialsRepository, mock(ChangePasswordRepository.class),
                notificationCodeRepository, mock(VerifyEmailRepository.class),
                mock(MfaUserRepository.class), notifier, new PasswordEncoderService());
    }

    private void primeSignupVerification() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-1");
        user.setUsername("alice");
        when(notificationCodeRepository.findByCodeAndType("code-1", "USER_SIGNUP"))
                .thenReturn(Optional.of(new NotificationCode("u-1", "code-1", "USER_SIGNUP")));
        when(userCredentialsRepository.findByUserId("u-1")).thenReturn(Optional.of(user));
    }

    @Test
    void userClaims_includesEmailAndUsername_alongsideAttributes() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-1");
        user.setUsername("alice");
        user.setEmail("alice@example.com");
        user.getUserAttributes().put("department", "Tax");
        when(userCredentialsRepository.findByUserId("u-1")).thenReturn(Optional.of(user));

        final Map<String, String> claims = service.userClaims("u-1");

        assertEquals("alice@example.com", claims.get("email"));
        assertEquals("alice", claims.get("username"));
        assertEquals("Tax", claims.get("department"));
    }

    @Test
    void userClaims_omitsEmail_whenNotSet() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-2");
        user.setUsername("svc-account");
        when(userCredentialsRepository.findByUserId("u-2")).thenReturn(Optional.of(user));

        final Map<String, String> claims = service.userClaims("u-2");

        assertFalse(claims.containsKey("email"), "no email column → no email claim");
        assertEquals("svc-account", claims.get("username"));
    }

    @Test
    void userClaims_doesNotOverrideExplicitAttribute() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-3");
        user.setUsername("alice");
        user.setEmail("column@example.com");
        // An explicit profile attribute wins over the column-derived default.
        user.getUserAttributes().put("email", "attr@example.com");
        when(userCredentialsRepository.findByUserId("u-3")).thenReturn(Optional.of(user));

        assertEquals("attr@example.com", service.userClaims("u-3").get("email"));
    }

    @Test
    void verifyEmail_doesNotSendInternalNotification_whenNoRecipientConfigured() {
        // Default: no hard-coded recipient (previously the leaked contact@kubedna.com) -> no notification.
        primeSignupVerification();

        service.verifyEmail("code-1");

        verify(notifier, never()).sendEmailNotification(any());
    }

    @Test
    void verifyEmail_sendsInternalNotification_toTheConfiguredRecipient() {
        ReflectionTestUtils.setField(service, "registrationNotificationRecipient", "ops@example.com");
        primeSignupVerification();

        service.verifyEmail("code-1");

        final ArgumentCaptor<NotificationRequest> captor = ArgumentCaptor.forClass(NotificationRequest.class);
        verify(notifier).sendEmailNotification(captor.capture());
        assertEquals("ops@example.com", captor.getValue().getEmailAddress());
    }
}
