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
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The delivery behaviour around {@link EmailDelivery}: the first attempt is synchronous; a transient failure is queued
 * and retried with backoff (same message id) until it succeeds, the code in the email expires or the retry window
 * closes; a permanent failure is never retried, and a bounce marks the user's address; the send rate caps refuse
 * (never silently drop) an email; and every step is counted and audited without the body.
 */
class EmailOutboxTest {

    private static final Instant START = Instant.parse("2026-09-27T10:00:00Z");
    private static final String LINK = "https://idp.example.com/login/magic/verify?token=secret-link-token";

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final HelixMetrics metrics = new HelixMetrics(registry);
    private final AuditLog audit = mock(AuditLog.class);
    private final MutableClock clock = new MutableClock(START);
    private final InMemoryEmailRetryStore store = new InMemoryEmailRetryStore();
    private final List<String> bounced = new ArrayList<>();
    private final EmailProperties props = new EmailProperties();
    private Map<String, String> realmConfig = new HashMap<>();

    /** A transport that answers from a script (the last answer repeats) and records every message. */
    private final class Scripted implements EmailTransport {
        final Deque<DeliveryResult> script = new ArrayDeque<>();
        final List<EmailMessage> messages = new ArrayList<>();
        final List<Instant> at = new ArrayList<>();

        Scripted answers(final DeliveryResult... results) {
            script.addAll(List.of(results));
            return this;
        }

        @Override
        public String driver() {
            return "FAKE";
        }

        @Override
        public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage message) {
            messages.add(message);
            at.add(clock.instant());
            return script.size() > 1 ? script.poll() : script.peek();
        }
    }

    private final Scripted transport = new Scripted();

    @BeforeEach
    void noJitter() {
        props.getRetry().setJitter(0);
    }

    private EmailOutbox outbox() {
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(new ResolvedProviderDto("EMAIL", "FAKE",
                "no-reply@acme.example", "Acme", realmConfig, "provider-secret")), List.of(transport), null, metrics,
                audit);
        return new EmailOutbox(delivery, store, new EmailSendRateCap(props.getRateLimit(), clock),
                (realm, address, at) -> {
                    bounced.add(realm + "|" + address);
                    return List.of("user-1");
                }, props, metrics, audit, clock);
    }

    private static EmailMessage message(final Instant expiresAt) {
        return EmailMessage.of(null, "ada@example.org", "Sign in to Acme",
                "<p><a href=\"" + LINK + "\">Sign in</a></p>", true, null).withExpiresAt(expiresAt);
    }

    private static DeliveryResult transientFailure() {
        return DeliveryResult.transientFailure(Reason.PROVIDER_ERROR, "HTTP 503");
    }

    private static DeliveryResult accepted() {
        return DeliveryResult.accepted("provider-1", "HTTP 200");
    }

    private double retries(final String outcome) {
        final var c = registry.find("helix_email_retry_total").tags("realm", "acme", "outcome", outcome).counter();
        return c == null ? 0 : c.count();
    }

    private List<AuditEvent> audited() {
        final ArgumentCaptor<AuditEvent> events = ArgumentCaptor.forClass(AuditEvent.class);
        verify(audit, atLeastOnce()).emit(events.capture());
        return events.getAllValues();
    }

    @Test
    void aTransientFailure_isRetriedAfterTheBackoff_withTheSameMessageId_untilItSucceeds() {
        transport.answers(transientFailure(), transientFailure(), accepted());
        final EmailOutbox outbox = outbox();

        final EmailSendOutcome outcome = outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        // The first attempt is synchronous: the caller gets the real result, and knows a retry is queued.
        assertThat(outcome.result().status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(outcome.retryScheduled()).isTrue();
        assertThat(outcome.inFlight()).isTrue();
        assertThat(store.all()).singleElement().satisfies(e -> {
            assertThat(e.attempts()).isEqualTo(1);
            assertThat(e.nextAttemptAt()).isEqualTo(START.plusSeconds(30));
            assertThat(e.giveUpAt()).isEqualTo(START.plus(Duration.ofHours(1)));
        });

        clock.advance(Duration.ofSeconds(29));
        assertThat(outbox.processDue()).isZero(); // not due yet
        clock.advance(Duration.ofSeconds(1));
        assertThat(outbox.processDue()).isEqualTo(1); // second attempt fails again: next wait is 2 minutes
        assertThat(store.all()).singleElement().satisfies(e -> {
            assertThat(e.attempts()).isEqualTo(2);
            assertThat(e.nextAttemptAt()).isEqualTo(START.plusSeconds(30 + 120));
        });
        clock.advance(Duration.ofSeconds(120));
        assertThat(outbox.processDue()).isEqualTo(1);

        assertThat(store.count()).isZero();
        assertThat(transport.messages).hasSize(3).extracting(EmailMessage::messageId).containsOnly(
                transport.messages.get(0).messageId());
        assertThat(transport.messages.get(2).html()).contains(LINK);
        assertThat(retries("scheduled")).isEqualTo(1.0);
        assertThat(retries("rescheduled")).isEqualTo(1.0);
        assertThat(retries("delivered")).isEqualTo(1.0);
        verify(audit, never()).emit(any());
    }

    @Test
    void theBackoffIs30s_2m_10m_30m_thenTheEmailIsGivenUp_andAudited() {
        transport.answers(transientFailure());
        final EmailOutbox outbox = outbox();
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        for (final Duration wait : List.of(Duration.ofSeconds(30), Duration.ofMinutes(2), Duration.ofMinutes(10),
                Duration.ofMinutes(30))) {
            clock.advance(wait);
            outbox.processDue();
        }

        assertThat(transport.at).containsExactly(START, START.plusSeconds(30), START.plusSeconds(150),
                START.plusSeconds(750), START.plusSeconds(2550));
        assertThat(store.count()).isZero();
        assertThat(retries("gave_up")).isEqualTo(1.0);
        clock.advance(Duration.ofHours(2));
        outbox.processDue();
        assertThat(transport.messages).hasSize(5);
        assertThat(audited()).singleElement().satisfies(e -> {
            assertThat(e.type()).isEqualTo("EMAIL_SEND_FAILED");
            assertThat(e.realm()).isEqualTo("acme");
            assertThat(e.resourceId()).isEqualTo(transport.messages.get(0).messageId());
            assertThat(e.detail()).containsEntry("stage", "gave-up").containsEntry("attempts", "5")
                    .containsEntry("reason", "PROVIDER_ERROR");
            assertThat(e.toString()).doesNotContain(LINK).doesNotContain("provider-secret")
                    .doesNotContain("ada@example.org");
        });
    }

    @Test
    void theJitter_spreadsEachDelayWithinItsFraction() {
        props.getRetry().setJitter(0.2);
        transport.answers(transientFailure());
        final EmailOutbox outbox = outbox();
        for (int i = 0; i < 20; i++) {
            outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        }
        assertThat(store.all()).hasSize(20).allSatisfy(e -> assertThat(e.nextAttemptAt())
                .isBetween(START.plusSeconds(24), START.plusSeconds(36)));
        // Spread, not all at the same instant (a thundering herd after an outage).
        assertThat(store.all().stream().map(EmailRetryStore.Entry::nextAttemptAt).distinct().count()).isGreaterThan(1);
    }

    @Test
    void aPermanentFailure_isNotRetried_andIsAudited() {
        transport.answers(DeliveryResult.permanent(Reason.MESSAGE_REJECTED, "HTTP 400: 10001 bad request"));
        final EmailOutbox outbox = outbox();

        final EmailSendOutcome outcome = outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(outcome.result().status()).isEqualTo(Status.PERMANENT_FAILURE);
        assertThat(outcome.retryScheduled()).isFalse();
        assertThat(outcome.inFlight()).isFalse();
        assertThat(store.count()).isZero();
        clock.advance(Duration.ofHours(2));
        outbox.processDue();
        assertThat(transport.messages).hasSize(1);
        assertThat(bounced).isEmpty();
        assertThat(audited()).singleElement().satisfies(e -> {
            assertThat(e.type()).isEqualTo("EMAIL_SEND_FAILED");
            assertThat(e.outcome()).isEqualTo("FAILURE");
            assertThat(e.detail()).containsEntry("status", "PERMANENT_FAILURE").containsEntry("reason",
                    "MESSAGE_REJECTED").containsEntry("stage", "first-attempt").containsEntry("diagnostic",
                    "HTTP 400: 10001 bad request");
            assertThat(e.toString()).doesNotContain(LINK).doesNotContain("Sign in to Acme");
        });
    }

    @Test
    void aBounce_marksTheUsersAddress_isAudited_andCounted_andNotRetried() {
        transport.answers(DeliveryResult.bounced(List.of("ada@example.org"), "permanent bounce"));
        final EmailOutbox outbox = outbox();

        final EmailSendOutcome outcome = outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(outcome.result().reason()).isEqualTo(Reason.RECIPIENT_BOUNCED);
        assertThat(store.count()).isZero();
        assertThat(bounced).containsExactly("acme|ada@example.org");
        assertThat(registry.find("helix_email_bounces_total").tags("realm", "acme").counter().count()).isEqualTo(1.0);
        assertThat(audited()).singleElement().satisfies(e -> {
            assertThat(e.type()).isEqualTo("EMAIL_BOUNCED");
            assertThat(e.resourceType()).isEqualTo("user");
            assertThat(e.resourceId()).isEqualTo("user-1");
            assertThat(e.toString()).doesNotContain(LINK);
        });
    }

    @Test
    void aBounceOnARetry_marksTheAddressToo() {
        transport.answers(transientFailure(), DeliveryResult.bounced(List.of("ada@example.org"), "bounced"));
        final EmailOutbox outbox = outbox();
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        clock.advance(Duration.ofSeconds(30));
        outbox.processDue();

        assertThat(bounced).containsExactly("acme|ada@example.org");
        assertThat(store.count()).isZero();
        assertThat(retries("permanent")).isEqualTo(1.0);
    }

    @Test
    void anEmailWhoseCodeHasExpired_isNeverSentAgain() {
        transport.answers(transientFailure(), accepted());
        final EmailOutbox outbox = outbox();
        // An OTP valid for 5 minutes: the 30 s retry is fine, the 2 min one too, but not after expiry.
        outbox.send("acme", message(START.plus(Duration.ofMinutes(1))), EmailOutbox.SendOptions.TRANSACTIONAL);
        assertThat(store.count()).isEqualTo(1);

        clock.advance(Duration.ofMinutes(2)); // the worker was down; the code expired meanwhile
        outbox.processDue();

        assertThat(transport.messages).hasSize(1);
        assertThat(store.count()).isZero();
        assertThat(retries("expired")).isEqualTo(1.0);
        assertThat(audited()).singleElement().satisfies(e -> assertThat(e.detail()).containsEntry("stage", "expired"));
    }

    @Test
    void noRetryIsQueued_whenItWouldBeDueOnlyAfterTheCodeExpires() {
        transport.answers(transientFailure());
        final EmailOutbox outbox = outbox();

        final EmailSendOutcome outcome = outbox.send("acme", message(START.plusSeconds(20)),
                EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(outcome.retryScheduled()).isFalse();
        assertThat(store.count()).isZero();
        assertThat(audited()).singleElement().satisfies(e -> assertThat(e.detail()).containsEntry("stage", "expired"));
    }

    @Test
    void aRetryIsNotSentAfterTheExpiry_evenWhenTheBackoffWouldAllowIt() {
        transport.answers(transientFailure());
        final EmailOutbox outbox = outbox();
        outbox.send("acme", message(START.plusSeconds(100)), EmailOutbox.SendOptions.TRANSACTIONAL);
        clock.advance(Duration.ofSeconds(30));

        outbox.processDue(); // second attempt fails; the third would be at 150 s > 100 s: given up

        assertThat(transport.messages).hasSize(2);
        assertThat(store.count()).isZero();
    }

    @Test
    void theAdminTestSend_isNeverRetried_andMarksNoBounce() {
        transport.answers(transientFailure());
        final EmailOutbox outbox = outbox();

        final EmailSendOutcome outcome = outbox.send("acme", message(null), EmailOutbox.SendOptions.TEST);

        assertThat(outcome.retryScheduled()).isFalse();
        assertThat(store.count()).isZero();
        transport.script.clear();
        transport.answers(DeliveryResult.bounced(List.of("ada@example.org"), "bounced"));
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TEST);
        assertThat(bounced).isEmpty();
        verify(audit, never()).emit(any());
    }

    @Test
    void noProvider_isNotQueued() {
        final EmailDelivery none = new EmailDelivery(realm -> List.of(), List.of(transport), null, metrics, audit);
        final EmailOutbox outbox = new EmailOutbox(none, store, null, null, props, metrics, audit, clock);

        final EmailSendOutcome outcome = outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(outcome.result().reason()).isEqualTo(Reason.NO_PROVIDER);
        assertThat(store.count()).isZero();
    }

    @Test
    void withRetriesDisabled_aTransientFailureIsReturned_andNotQueued() {
        props.getRetry().setEnabled(false);
        transport.answers(transientFailure());

        final EmailSendOutcome outcome = outbox().send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(outcome.retryScheduled()).isFalse();
        assertThat(store.count()).isZero();
    }

    @Test
    void theRealmRateCap_refusesTheEmail_withAClearResult_countsAndAuditsIt() {
        props.getRateLimit().setRealmPerMinute(2);
        transport.answers(accepted());
        final EmailOutbox outbox = outbox();

        assertThat(outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL).inFlight()).isTrue();
        assertThat(outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL).inFlight()).isTrue();
        final EmailSendOutcome capped = outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(capped.result().status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(capped.result().reason()).isEqualTo(Reason.RATE_CAPPED);
        assertThat(capped.result().diagnostic()).contains("2 emails per minute");
        assertThat(capped.retryScheduled()).isFalse();
        assertThat(capped.inFlight()).isFalse();
        assertThat(transport.messages).hasSize(2); // nothing reached the provider
        assertThat(store.count()).isZero(); // and nothing is queued
        assertThat(registry.find("helix_email_rate_capped_total").tags("realm", "acme", "scope", "realm").counter()
                .count()).isEqualTo(2.0);
        // Audited once per realm and minute, not once per refused email (a flood must not flood the audit log).
        assertThat(audited()).singleElement().satisfies(e -> {
            assertThat(e.type()).isEqualTo("EMAIL_SEND_RATE_CAPPED");
            assertThat(e.detail()).containsEntry("scope", "realm").containsEntry("limitPerMinute", "2");
        });
        // Other realms have their own budget.
        assertThat(outbox.send("other", message(null), EmailOutbox.SendOptions.TRANSACTIONAL).inFlight()).isTrue();
        // The budget refills over the minute.
        clock.advance(Duration.ofSeconds(31));
        assertThat(outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL).inFlight()).isTrue();
    }

    @Test
    void aRealmsOwnSendLimit_fromItsProviderSettings_overridesTheDefault() {
        props.getRateLimit().setRealmPerMinute(100);
        realmConfig = Map.of("sendLimitPerMinute", "1");
        transport.answers(accepted());
        final EmailOutbox outbox = outbox();

        assertThat(outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL).inFlight()).isTrue();
        assertThat(outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL).result().reason())
                .isEqualTo(Reason.RATE_CAPPED);
    }

    @Test
    void theGlobalRateCap_coversAllRealms() {
        props.getRateLimit().setGlobalPerMinute(3);
        transport.answers(accepted());
        final EmailOutbox outbox = outbox();

        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        outbox.send("globex", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        outbox.send(null, message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        final EmailSendOutcome capped = outbox.send("initech", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(capped.result().reason()).isEqualTo(Reason.RATE_CAPPED);
        assertThat(capped.result().diagnostic()).contains("server");
        assertThat(registry.find("helix_email_rate_capped_total").tags("scope", "global").counter().count())
                .isEqualTo(1.0);
    }

    @Test
    void retriesAreNotRateCapped() {
        props.getRateLimit().setRealmPerMinute(1);
        transport.answers(transientFailure(), accepted());
        final EmailOutbox outbox = outbox();
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);

        clock.advance(Duration.ofSeconds(30));
        outbox.processDue();

        assertThat(transport.messages).hasSize(2);
        assertThat(retries("delivered")).isEqualTo(1.0);
    }

    @Test
    void metrics_sendTotal_latency_retries_andTheQueuedGauge() {
        transport.answers(transientFailure(), accepted());
        final EmailOutbox outbox = outbox();
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        outbox.refreshQueueGauge();

        final Gauge queued = registry.find("helix_email_retry_queued").gauge();
        assertThat(queued).isNotNull();
        assertThat(queued.value()).isEqualTo(1.0);
        clock.advance(Duration.ofSeconds(30));
        outbox.processDue();
        assertThat(queued.value()).isZero();

        assertThat(registry.find("helix_email_send_total").tags("realm", "acme", "driver", "FAKE", "result",
                "TRANSIENT_FAILURE").counter().count()).isEqualTo(1.0);
        assertThat(registry.find("helix_email_send_total").tags("realm", "acme", "driver", "FAKE", "result",
                "ACCEPTED").counter().count()).isEqualTo(1.0);
        final Timer latency = registry.find("helix_email_send_duration").tags("realm", "acme", "driver", "FAKE").timer();
        assertThat(latency).isNotNull();
        assertThat(registry.find("helix_email_send_duration").timers().stream().mapToLong(Timer::count).sum())
                .isEqualTo(2);
        assertThat(latency.totalTime(TimeUnit.NANOSECONDS)).isGreaterThanOrEqualTo(0);
        assertThat(retries("scheduled")).isEqualTo(1.0);
        assertThat(retries("delivered")).isEqualTo(1.0);
    }

    @Test
    void aWorkerThatLostItsClaim_doesNotFinishTheEntry() {
        transport.answers(transientFailure());
        final EmailOutbox outbox = outbox();
        outbox.send("acme", message(null), EmailOutbox.SendOptions.TRANSACTIONAL);
        clock.advance(Duration.ofSeconds(30));
        final List<EmailRetryStore.Entry> claimed = store.claim(clock.instant(), Duration.ofMinutes(2), 10, "other");

        assertThat(claimed).hasSize(1);
        assertThat(outbox.processDue()).isZero(); // claimed by another worker: skipped
        assertThat(transport.messages).hasSize(1);
    }
}
