/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.messaging.email.DeliveryResult.Status;
import io.helixiam.authorization.observability.HelixMetrics;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.notification.delivery.SmtpProperties;
import io.helixiam.testsupport.LogCapture;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The email entry point: the realm's provider first, then the global default; one classified result per attempt,
 * counted in {@code helix_email_send_total{realm,driver,result}}; refused credentials raise a metric, a WARN log and
 * an audit event; the secret never reaches a diagnostic or a log.
 */
class EmailDeliveryTest {

    private static final String SECRET = "provider-secret-4411";

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final HelixMetrics metrics = new HelixMetrics(registry);
    private final AuditLog audit = mock(AuditLog.class);

    /** A transport that answers what {@code answer} says and records what it was given. */
    private static final class Fake implements EmailTransport {
        final String id;
        final Function<EmailMessage, DeliveryResult> answer;
        final List<ResolvedProviderDto> providers = new ArrayList<>();
        final List<EmailMessage> messages = new ArrayList<>();

        Fake(final String id, final Function<EmailMessage, DeliveryResult> answer) {
            this.id = id;
            this.answer = answer;
        }

        @Override
        public String driver() {
            return id;
        }

        @Override
        public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage message) {
            providers.add(provider);
            messages.add(message);
            return answer.apply(message);
        }
    }

    private static ResolvedProviderDto realmProvider(final String driver) {
        return new ResolvedProviderDto("EMAIL", driver, "no-reply@acme.example", "Acme", Map.of(), SECRET);
    }

    private static GlobalEmailProvider globalSmtp() {
        final SmtpProperties smtp = new SmtpProperties();
        smtp.setHost("smtp.example.com");
        return new GlobalEmailProvider(new EmailProperties(), smtp, new CloudflareProperties());
    }

    private static EmailMessage message() {
        return EmailMessage.of(null, "ada@example.org", "Hi", "<p>x</p>", true, null);
    }

    private double count(final String realm, final String driver, final String result) {
        final var c = registry.find("helix_email_send_total").tags("realm", realm, "driver", driver, "result", result)
                .counter();
        return c == null ? 0 : c.count();
    }

    @Test
    void theRealmProviderWins_overTheGlobalDefault() {
        final Fake cloudflare = new Fake("CLOUDFLARE", m -> DeliveryResult.accepted("cf-1", "HTTP 200"));
        final Fake smtp = new Fake("SMTP", m -> DeliveryResult.accepted(null, null));
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(realmProvider("CLOUDFLARE")),
                List.of(cloudflare, smtp), globalSmtp(), metrics, audit);

        final DeliveryResult result = delivery.deliver("acme", message());

        assertThat(result.status()).isEqualTo(Status.ACCEPTED);
        assertThat(cloudflare.messages).hasSize(1);
        assertThat(smtp.messages).isEmpty();
        assertThat(count("acme", "CLOUDFLARE", "ACCEPTED")).isEqualTo(1.0);
    }

    @Test
    void withoutARealmProvider_theGlobalDefaultIsUsed() {
        final Fake smtp = new Fake("SMTP", m -> DeliveryResult.accepted(null, null));
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(), List.of(smtp), globalSmtp(), metrics, audit);

        assertThat(delivery.deliver("acme", message()).status()).isEqualTo(Status.ACCEPTED);
        assertThat(delivery.deliver(null, message()).status()).isEqualTo(Status.ACCEPTED);
        assertThat(smtp.providers).extracting(p -> p.config().get("host")).containsOnly("smtp.example.com");
        assertThat(delivery.realmProvider("acme")).isEmpty();
    }

    @Test
    void aRealmProviderWithAnUnknownDriver_fallsBackToTheGlobalDefault() {
        final Fake smtp = new Fake("SMTP", m -> DeliveryResult.accepted(null, null));
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(realmProvider("CARRIER_PIGEON")),
                List.of(smtp), globalSmtp(), metrics, audit);

        assertThat(delivery.deliver("acme", message()).status()).isEqualTo(Status.ACCEPTED);
        assertThat(smtp.messages).hasSize(1);
    }

    @Test
    void noProviderAnywhere_isNoProvider_andNotCounted() {
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(), List.of(),
                new GlobalEmailProvider(null, null, null), metrics, audit);

        final DeliveryResult result = delivery.deliver("acme", message());

        assertThat(result.status()).isEqualTo(Status.PERMANENT_FAILURE);
        assertThat(result.reason()).isEqualTo(Reason.NO_PROVIDER);
        assertThat(registry.find("helix_email_send_total").counters()).isEmpty();
    }

    @Test
    void aThrowingOrSilentDriver_isATransientFailure() {
        final EmailDelivery throwing = new EmailDelivery(realm -> List.of(realmProvider("X")),
                List.of(new Fake("X", m -> {
                    throw new IllegalStateException("boom " + SECRET);
                })), null, metrics, audit);
        final DeliveryResult r1 = throwing.deliver("acme", message());
        assertThat(r1.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(r1.diagnostic()).doesNotContain(SECRET);

        final EmailDelivery silent = new EmailDelivery(realm -> List.of(realmProvider("X")),
                List.of(new Fake("X", m -> null)), null, metrics, audit);
        assertThat(silent.deliver("acme", message()).status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(count("acme", "X", "TRANSIENT_FAILURE")).isEqualTo(2.0);
    }

    @Test
    void refusedCredentials_raiseAMetric_aWarning_andAnAuditEvent_withoutTheSecret() {
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(realmProvider("CLOUDFLARE")),
                List.of(new Fake("CLOUDFLARE", m -> DeliveryResult.transientFailure(Reason.AUTHENTICATION,
                        "HTTP 401: 10000 bad token " + SECRET))), null, metrics, audit);

        final DeliveryResult result;
        try (LogCapture logs = LogCapture.of(EmailDelivery.class)) {
            result = delivery.deliver("acme", message());
            assertThat(logs.text()).contains("ACTION NEEDED").contains("CLOUDFLARE").doesNotContain(SECRET);
        }

        assertThat(result.status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(result.diagnostic()).doesNotContain(SECRET).contains("***");
        assertThat(registry.find("helix_email_provider_auth_failures_total").tags("realm", "acme", "driver", "CLOUDFLARE")
                .counter().count()).isEqualTo(1.0);
        assertThat(count("acme", "CLOUDFLARE", "TRANSIENT_FAILURE")).isEqualTo(1.0);
        final ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit).emit(event.capture());
        assertThat(event.getValue().type()).isEqualTo("EMAIL_PROVIDER_AUTH_FAILED");
        assertThat(event.getValue().realm()).isEqualTo("acme");
        assertThat(event.getValue().outcome()).isEqualTo("FAILURE");
        assertThat(event.getValue().toString()).doesNotContain(SECRET).doesNotContain("<p>x</p>");
    }

    @Test
    void otherFailures_raiseNoAuditEvent() {
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(realmProvider("SMTP")),
                List.of(new Fake("SMTP", m -> DeliveryResult.transientFailure(Reason.NETWORK, "timed out"))), null,
                metrics, audit);

        delivery.deliver("acme", message());

        verify(audit, never()).emit(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void theMessageIdIsKept_acrossAttempts() {
        final Fake fake = new Fake("SMTP", m -> DeliveryResult.transientFailure(Reason.NETWORK, "down"));
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(realmProvider("SMTP")), List.of(fake), null,
                metrics, audit);
        final EmailMessage message = message();

        delivery.deliver("acme", message);
        delivery.deliver("acme", message);

        assertThat(fake.messages).extracting(EmailMessage::messageId).containsExactly(message.messageId(),
                message.messageId());
    }

    @Test
    void theProviderIsReadAtEverySend_soARotatedSecretAppliesAtOnce() {
        final String[] secret = {"old-secret"};
        final Fake fake = new Fake("CLOUDFLARE", m -> DeliveryResult.accepted(null, null));
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(new ResolvedProviderDto("EMAIL", "CLOUDFLARE",
                "no-reply@acme.example", null, Map.of(), secret[0])), List.of(fake), null, metrics, audit);

        delivery.deliver("acme", message());
        secret[0] = "new-secret";
        delivery.deliver("acme", message());

        assertThat(fake.providers).extracting(ResolvedProviderDto::secret).containsExactly("old-secret", "new-secret");
    }
}
