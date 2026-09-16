/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.notification.delivery;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.domain.messaging.MessagingProvider;
import io.helixiam.authorization.messaging.driver.EmailDriver;
import io.helixiam.authorization.repository.messaging.MessagingProviderRepository;
import io.helixiam.authorization.security.realm.RealmContextHolder;
import io.helixiam.notification.delivery.spi.AppSender;
import io.helixiam.notification.delivery.spi.SmsSender;
import io.helixiam.notification.domain.NotificationCode;
import io.helixiam.notification.domain.NotificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Task 4 (strip-RabbitMQ notification delivery). Verifies {@link SmtpNotifier}'s message
 * construction and provider-resolution logic — realm provider takes precedence over the global SMTP
 * fallback, no provider configured is a no-op (not an exception), and a driver failure never
 * propagates out of any {@code send*} method. No SMTP server is ever dialed: {@link EmailDriver} and
 * {@link SmsSender} are captured with hand-written test doubles (mirroring the
 * {@code SmtpEmailDriver.MailTransport} seam already used by
 * {@code io.helixiam.authorization.messaging.driver.SmtpEmailDriverTest}-style tests in this codebase),
 * and {@link MessagingProviderRepository} is mocked (it is a Spring Data interface, not something you
 * can hand-instantiate).
 */
class SmtpNotifierTest {

    private final RecordingEmailDriver smtpDriver = new RecordingEmailDriver("SMTP");
    private final RecordingEmailDriver httpDriver = new RecordingEmailDriver("HTTP");
    private final MessagingProviderRepository providerRepository = mock(MessagingProviderRepository.class);
    private final SmtpProperties smtpProperties = new SmtpProperties();

    @BeforeEach
    void clearRealm() {
        RealmContextHolder.clear();
    }

    @AfterEach
    void tearDown() {
        RealmContextHolder.clear();
    }

    private SmtpNotifier notifier(final SmsSender smsSender, final AppSender appSender) {
        return new SmtpNotifier(List.of(smtpDriver, httpDriver), providerRepository, smsSender, appSender, smtpProperties);
    }

    @Test
    void composesTypeSpecificSubjectAndBodyWithCode() {
        final NotificationMessageComposer.ComposedMessage resetMessage = NotificationMessageComposer.compose(
                requestWithCode("USER_RESET_PASSWORD", "ABC123"));
        assertThat(resetMessage.subject()).isEqualTo("Reset your HelixIAM password");
        assertThat(resetMessage.body()).contains("ABC123");

        final NotificationMessageComposer.ComposedMessage signupMessage = NotificationMessageComposer.compose(
                requestWithCode("USER_SIGNUP", "XYZ789"));
        assertThat(signupMessage.subject()).contains("verify your account");
        assertThat(signupMessage.body()).contains("XYZ789");

        final NotificationMessageComposer.ComposedMessage unknownMessage = NotificationMessageComposer.compose(
                requestWithCode("SOME_OTHER_TYPE", "CODE1"));
        assertThat(unknownMessage.subject()).contains("SOME_OTHER_TYPE");
        assertThat(unknownMessage.body()).contains("CODE1");
    }

    @Test
    void sendsEmailViaGlobalSmtpWhenNoRealmProviderIsConfigured() {
        smtpProperties.setHost("smtp.example.com");
        smtpProperties.setFromAddress("no-reply@helix.test");
        // No realm in context -> RealmContextHolder.get() == null -> global fallback only.
        when(providerRepository.findByRealmIdAndChannel("does-not-matter", "EMAIL")).thenReturn(List.of());

        notifier(failingSmsSender(), failingAppSender())
                .sendEmailNotification(requestWithCode("USER_RESET_PASSWORD", "CODE42"));

        assertThat(smtpDriver.sent).hasSize(1);
        final Sent sent = smtpDriver.sent.get(0);
        assertThat(sent.to()).isEqualTo("user@example.com");
        assertThat(sent.subject()).isEqualTo("Reset your HelixIAM password");
        assertThat(sent.body()).contains("CODE42");
        assertThat(sent.provider().config().get("host")).isEqualTo("smtp.example.com");
        assertThat(httpDriver.sent).isEmpty();
    }

    @Test
    void realmProviderTakesPrecedenceOverGlobalSmtpAndPicksMatchingDriver() {
        RealmContextHolder.set("acme");
        // Global SMTP IS also configured, to prove the realm provider wins.
        smtpProperties.setHost("global-smtp.example.com");

        final MessagingProvider realmProvider = new MessagingProvider();
        realmProvider.setRealmId("acme");
        realmProvider.setChannel("EMAIL");
        realmProvider.setDriver("HTTP");
        realmProvider.setEnabled(true);
        realmProvider.setFromAddress("noreply@acme.example");
        realmProvider.setConfig("{\"url\":\"https://mail.acme.example/send\"}");
        realmProvider.setSecret("acme-secret");
        when(providerRepository.findByRealmIdAndChannel("acme", "EMAIL")).thenReturn(List.of(realmProvider));

        notifier(failingSmsSender(), failingAppSender())
                .sendEmailNotification(requestWithCode("USER_SIGNUP", "REALM1"));

        assertThat(httpDriver.sent).hasSize(1);
        assertThat(httpDriver.sent.get(0).provider().fromAddress()).isEqualTo("noreply@acme.example");
        assertThat(httpDriver.sent.get(0).provider().secret()).isEqualTo("acme-secret");
        assertThat(smtpDriver.sent).isEmpty();
    }

    @Test
    void dropsEmailWithoutThrowingWhenNothingIsConfigured() {
        when(providerRepository.findByRealmIdAndChannel("nowhere", "EMAIL")).thenReturn(List.of());
        // smtpProperties.host left blank (default): no realm, no global fallback.

        notifier(failingSmsSender(), failingAppSender())
                .sendEmailNotification(requestWithCode("USER_SIGNUP", "CODE"));

        assertThat(smtpDriver.sent).isEmpty();
        assertThat(httpDriver.sent).isEmpty();
    }

    @Test
    void driverFailureIsCaughtAndDoesNotPropagate() {
        smtpProperties.setHost("smtp.example.com");
        smtpDriver.throwOnSend = true;

        // Must not throw: a downed mail server must never fail the caller (e.g. signup/reset-password).
        notifier(failingSmsSender(), failingAppSender())
                .sendEmailNotification(requestWithCode("USER_SIGNUP", "CODE"));
    }

    @Test
    void logsAndSkipsSmsWhenSenderReportsNothingConfigured() {
        final NotificationRequest request = requestWithCode("USER_SIGNUP", "CODE");
        request.setMobile("+15551234567");

        // Must not throw even though the SmsSender reports nothing was actually dispatched.
        notifier((to, message) -> false, failingAppSender()).sendSmsNotification(request);
    }

    @Test
    void appNotificationDelegatesToAppSender() {
        final NotificationRequest request = requestWithCode("USER_SIGNUP", "CODE");
        request.setDeviceId("device-123");
        final List<String> delivered = new ArrayList<>();

        notifier(failingSmsSender(), (deviceId, title, body) -> delivered.add(deviceId + ":" + title))
                .sendAppNotification(request);

        assertThat(delivered).hasSize(1).first().asString().startsWith("device-123:");
    }

    private static NotificationRequest requestWithCode(final String type, final String code) {
        final NotificationRequest request = new NotificationRequest(type);
        request.setEmailAddress("user@example.com");
        request.setNotificationCode(new NotificationCode("user-1", code, type));
        return request;
    }

    private static SmsSender failingSmsSender() {
        return (to, message) -> {
            throw new AssertionError("SMS should not be sent in this test");
        };
    }

    private static AppSender failingAppSender() {
        return (deviceId, title, body) -> {
            throw new AssertionError("Push should not be sent in this test");
        };
    }

    private record Sent(String to, String subject, String body, boolean html, ResolvedProviderDto provider) {
    }

    /** Hand-written {@link EmailDriver} test double — captures sends instead of dialing SMTP/HTTP. */
    private static final class RecordingEmailDriver implements EmailDriver {
        private final String driverId;
        private final List<Sent> sent = new ArrayList<>();
        private boolean throwOnSend;

        RecordingEmailDriver(final String driverId) {
            this.driverId = driverId;
        }

        @Override
        public String driver() {
            return driverId;
        }

        @Override
        public void send(final ResolvedProviderDto provider, final String to, final String subject, final String body,
                         final boolean html) {
            if (throwOnSend) {
                throw new IllegalStateException("simulated SMTP failure");
            }
            sent.add(new Sent(to, subject, body, html, provider));
        }
    }
}
