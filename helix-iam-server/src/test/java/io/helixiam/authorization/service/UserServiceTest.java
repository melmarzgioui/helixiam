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
    private ChangePasswordRepository changePasswords;

    /** A code that expires {@code validFor} from now (negative: already expired). */
    private static NotificationCode code(final String userId, final String code, final String type,
                                         final java.time.Duration validFor) {
        final NotificationCode c = new NotificationCode(userId, code, type);
        c.setExpiresAt(java.util.Date.from(java.time.Instant.now().plus(validFor)));
        return c;
    }

    private static io.helixiam.authorization.domain.user.ChangePassword reset(final String code) {
        final io.helixiam.authorization.domain.user.ChangePassword change =
                new io.helixiam.authorization.domain.user.ChangePassword();
        ReflectionTestUtils.setField(change, "code", code);
        change.setNewPassword("N3w-Passw0rd!long");
        return change;
    }

    @BeforeEach
    void setUp() {
        userCredentialsRepository = mock(UserCredentialsRepository.class);
        notificationCodeRepository = mock(NotificationCodeRepository.class);
        notifier = mock(Notifier.class);
        changePasswords = mock(ChangePasswordRepository.class);
        service = new UserService(userCredentialsRepository, changePasswords,
                notificationCodeRepository, mock(VerifyEmailRepository.class),
                mock(MfaUserRepository.class), notifier, new PasswordEncoderService());
    }

    private void primeSignupVerification() {
        final UserCredentials user = new UserCredentials();
        user.setUserId("u-1");
        user.setUsername("alice");
        when(notificationCodeRepository.findByCodeAndType("code-1", "USER_SIGNUP"))
                .thenReturn(Optional.of(code("u-1", "code-1", "USER_SIGNUP", java.time.Duration.ofHours(1))));
        when(notificationCodeRepository.consume("code-1", "USER_SIGNUP")).thenReturn(1);
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
        // Default: no hard-coded recipient (previously a leaked hard-coded address) -> no notification.
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

    @Test
    void verifyEmail_saysWhetherTheCodeWasAPendingVerification() {
        primeSignupVerification();
        org.junit.jupiter.api.Assertions.assertTrue(service.verifyEmail("code-1"));
        when(notificationCodeRepository.findByCodeAndType("wrong", "USER_SIGNUP")).thenReturn(Optional.empty());
        assertFalse(service.verifyEmail("wrong"));
        assertFalse(service.verifyEmail(" "));
        assertFalse(service.verifyEmail(null));
    }

    @Test
    void verifyEmailFor_returnsTheVerifiedUsername_orNullForAnUnknownCode() {
        primeSignupVerification();
        assertEquals("alice", service.verifyEmailFor("code-1"));
        when(notificationCodeRepository.findByCodeAndType("wrong", "USER_SIGNUP")).thenReturn(Optional.empty());
        org.junit.jupiter.api.Assertions.assertNull(service.verifyEmailFor("wrong"));
    }

    @Test
    void aValidResetCode_setsThePassword_once() {
        when(notificationCodeRepository.findByCodeAndType("r-1", "USER_RESET_PASSWORD"))
                .thenReturn(Optional.of(code("u-1", "r-1", "USER_RESET_PASSWORD", java.time.Duration.ofMinutes(30))));
        when(notificationCodeRepository.consume("r-1", "USER_RESET_PASSWORD")).thenReturn(1, 0);

        org.junit.jupiter.api.Assertions.assertTrue(service.resetPasswordUpdate(reset("r-1")));
        verify(changePasswords).save(any());
        // Single use: the code was consumed, a second use is refused.
        assertFalse(service.resetPasswordUpdate(reset("r-1")));
        verify(changePasswords, org.mockito.Mockito.times(1)).save(any());
    }

    @Test
    void anUnknownResetCode_isRefused() {
        when(notificationCodeRepository.findByCodeAndType(any(), any())).thenReturn(Optional.empty());

        assertFalse(service.resetPasswordUpdate(reset("nope")));
        assertFalse(service.resetPasswordUpdate(reset(null)));
        verify(changePasswords, never()).save(any());
    }

    @Test
    void anExpiredResetCode_isRefused_andRemoved() {
        final NotificationCode expired = code("u-1", "r-2", "USER_RESET_PASSWORD", java.time.Duration.ofMinutes(-1));
        when(notificationCodeRepository.findByCodeAndType("r-2", "USER_RESET_PASSWORD")).thenReturn(Optional.of(expired));

        assertFalse(service.resetPasswordUpdate(reset("r-2")));
        verify(changePasswords, never()).save(any());
        verify(notificationCodeRepository).consume("r-2", "USER_RESET_PASSWORD");
    }

    @Test
    void aResetCodeIssuedBeforeExpiriesWereStored_expiresAnHourAfterItWasCreated() {
        final NotificationCode legacy = new NotificationCode("u-1", "r-3", "USER_RESET_PASSWORD");
        legacy.setCreationDate(java.util.Date.from(java.time.Instant.now().minus(java.time.Duration.ofHours(2))));
        when(notificationCodeRepository.findByCodeAndType("r-3", "USER_RESET_PASSWORD")).thenReturn(Optional.of(legacy));

        assertFalse(service.resetPasswordUpdate(reset("r-3")));
        verify(changePasswords, never()).save(any());
    }

    @Test
    void anExpiredSignupCode_doesNotVerify() {
        when(notificationCodeRepository.findByCodeAndType("s-1", "USER_SIGNUP"))
                .thenReturn(Optional.of(code("u-1", "s-1", "USER_SIGNUP", java.time.Duration.ofSeconds(-5))));

        org.junit.jupiter.api.Assertions.assertNull(service.verifyEmailFor("s-1"));
    }
}
