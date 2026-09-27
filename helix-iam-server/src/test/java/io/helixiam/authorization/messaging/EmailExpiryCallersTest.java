/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging;

import io.helixiam.authorization.amqp.messaging.MessagingAdminPublisher;
import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.EmailDeliveryException;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailOutbox;
import io.helixiam.authorization.messaging.email.EmailSendOutcome;
import io.helixiam.authorization.messaging.sender.RealmEmailOtpSender;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.authorization.service.UserInfoService;
import io.helixiam.authorization.service.emailverification.EmailVerificationMessage;
import io.helixiam.authorization.service.emailverification.RealmEmailVerificationSender;
import io.helixiam.authorization.service.magiclink.MagicLinkMessage;
import io.helixiam.authorization.service.magiclink.RealmMagicLinkSender;
import io.helixiam.notification.Notifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Every email that carries a code or link tells the outbox when it stops working, so a retry never sends a dead one:
 * the OTP (5 minutes), the magic link (its TTL), the verification link (its TTL), the email-change link (24 hours);
 * and {@link MessagingService} turns that into {@link EmailMessage#expiresAt()}.
 */
class EmailExpiryCallersTest {

    private final MessagingService messaging = mock(MessagingService.class);
    private final UserInfoService userInfo = mock(UserInfoService.class);

    @AfterEach
    void clearRealm() {
        RealmContextHolder.clear();
    }

    @Test
    void theMagicLink_isNotRetriedAfterItsTtl() {
        when(messaging.sendEmail(any(), any(), any(), anyMap(), any())).thenReturn(true);

        new RealmMagicLinkSender(messaging, userInfo).send(new MagicLinkMessage("acme", "u1", "ada@example.org",
                "https://idp.example.com/login/magic/verify?token=t", 15));

        verify(messaging).sendEmail(eq("acme"), eq("ada@example.org"), eq("magic-link-email"), anyMap(),
                eq(Duration.ofMinutes(15)));
    }

    @Test
    void theVerificationLink_isNotRetriedAfterItsTtl() {
        when(messaging.sendEmail(any(), any(), any(), anyMap(), any())).thenReturn(true);

        new RealmEmailVerificationSender(messaging, mock(Notifier.class)).send(new EmailVerificationMessage("acme",
                "u1", "ada@example.org", "https://idp.example.com/verify-email?token=t", 24));

        verify(messaging).sendEmail(eq("acme"), eq("ada@example.org"), eq(RealmEmailVerificationSender.TEMPLATE),
                anyMap(), eq(Duration.ofHours(24)));
    }

    @Test
    void theEmailOtp_isNotRetriedAfterFiveMinutes() {
        RealmContextHolder.set("acme");
        when(userInfo.getOidcClaimProfile("u1")).thenReturn(Map.of("email", "ada@example.org"));
        when(messaging.sendEmail(any(), any(), any(), anyMap(), any())).thenReturn(true);

        new RealmEmailOtpSender(messaging, userInfo).send("u1", "123456");

        verify(messaging).sendEmail(eq("acme"), eq("ada@example.org"), eq("otp-email"), anyMap(),
                eq(Duration.ofMinutes(5)));
    }

    private MessagingService realService(final EmailOutbox outbox) {
        final MessagingAdminPublisher publisher = mock(MessagingAdminPublisher.class);
        when(publisher.listTemplates("acme")).thenReturn(List.of());
        final MessagingService service = new MessagingService(publisher, List.of(), List.of(), List.of());
        service.setEmailOutbox(outbox);
        when(outbox.realmProvider("acme")).thenReturn(Optional.of(new ResolvedProviderDto("EMAIL", "SMTP",
                "no-reply@acme.example.com", null, Map.of(), null)));
        return service;
    }

    @Test
    void sendEmail_givesTheMessageItsExpiry_andCountsAQueuedRetryAsInFlight() {
        final EmailOutbox outbox = mock(EmailOutbox.class);
        final MessagingService service = realService(outbox);
        when(outbox.send(eq("acme"), any(), eq(EmailOutbox.SendOptions.TRANSACTIONAL))).thenReturn(
                new EmailSendOutcome(DeliveryResult.transientFailure(DeliveryResult.Reason.NETWORK, "timeout"), true));
        final Instant before = Instant.now();

        assertThat(service.sendEmail("acme", "ada@example.org", "otp-email", Map.of("code", "1"),
                Duration.ofMinutes(5))).isTrue();

        final ArgumentCaptor<EmailMessage> sent = ArgumentCaptor.forClass(EmailMessage.class);
        verify(outbox).send(eq("acme"), sent.capture(), eq(EmailOutbox.SendOptions.TRANSACTIONAL));
        assertThat(sent.getValue().expiresAt()).isBetween(before.plus(Duration.ofMinutes(5)),
                Instant.now().plus(Duration.ofMinutes(5)));
    }

    @Test
    void sendEmail_throwsWithTheResult_whenTheEmailIsNeitherTakenNorQueued() {
        final EmailOutbox outbox = mock(EmailOutbox.class);
        final MessagingService service = realService(outbox);
        final DeliveryResult capped = DeliveryResult.transientFailure(DeliveryResult.Reason.RATE_CAPPED, "cap");
        when(outbox.send(eq("acme"), any(), any())).thenReturn(new EmailSendOutcome(capped, false));

        assertThatThrownBy(() -> service.sendEmail("acme", "ada@example.org", "otp-email", Map.of()))
                .isInstanceOfSatisfying(EmailDeliveryException.class, e -> assertThat(e.result()).isEqualTo(capped));
    }

    @Test
    void theAdminTestSend_isOneAttempt_neverQueued() {
        final EmailOutbox outbox = mock(EmailOutbox.class);
        final MessagingService service = realService(outbox);
        when(outbox.send(eq("acme"), any(), any(EmailMessage.class), eq(EmailOutbox.SendOptions.TEST))).thenReturn(
                new EmailSendOutcome(DeliveryResult.accepted(null, null), false));

        assertThat(service.sendEmailWithResult("acme", "ada@example.org", "otp-email", Map.of())).isPresent();

        verify(outbox).send(eq("acme"), any(), any(EmailMessage.class), eq(EmailOutbox.SendOptions.TEST));
    }
}
