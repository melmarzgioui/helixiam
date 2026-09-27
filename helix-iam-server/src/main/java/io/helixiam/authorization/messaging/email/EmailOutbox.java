/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.messaging.email;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.email.DeliveryResult.Reason;
import io.helixiam.authorization.observability.HelixMetrics;
import io.helixiam.authorization.security.audit.AuditContext;
import io.helixiam.authorization.security.audit.AuditEvent;
import io.helixiam.authorization.security.audit.AuditLog;
import io.helixiam.common.log.LogSafe;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * How HelixIAM sends an email: {@link #send} is what callers use; {@link EmailDelivery} does one attempt.
 *
 * <ol>
 *   <li><b>Rate caps.</b> The realm's and the server's send rate caps ({@link EmailSendRateCap}) are checked first.
 *       A capped email is refused with {@code TRANSIENT_FAILURE / RATE_CAPPED}, counted in
 *       {@code helix_email_rate_capped_total{realm,scope}} and audited ({@code EMAIL_SEND_RATE_CAPPED}, at most once
 *       per realm and minute). It is not queued.</li>
 *   <li><b>First attempt, synchronous.</b> The caller (and the admin test endpoint) gets the real classified
 *       result.</li>
 *   <li><b>Retries.</b> A {@code TRANSIENT_FAILURE} is stored in the {@link EmailRetryStore} (the rendered message,
 *       its body encrypted at rest) and sent again after each configured delay (30 s, 2 min, 10 min, 30 min by
 *       default, with jitter), with the same message id, until it is accepted, fails permanently, the code in it
 *       expires ({@link EmailMessage#expiresAt()}), or the retry window ({@code max-age}, 1 hour) closes. The
 *       {@link EmailRetryWorker} of every replica calls {@link #processDue}; a claim makes sure one replica sends each
 *       retry.</li>
 *   <li><b>Permanent failures</b> are never retried. They are audited ({@code EMAIL_SEND_FAILED}); a bounce marks the
 *       recipient's address as bounced on the user ({@link BounceRecorder}), is counted in
 *       {@code helix_email_bounces_total} and audited ({@code EMAIL_BOUNCED}).</li>
 * </ol>
 *
 * <p>Delivery is at least once: a replica that dies after the provider accepted an email but before it recorded that,
 * or a provider that accepted an email but answered with an error, leads to a second copy. SMTP carries the stable
 * {@code Message-ID}; API providers without an idempotency key (Cloudflare) may deliver both. Audit events and logs
 * never carry the body, the subject or a secret.
 */
public class EmailOutbox {

    /** How one email is sent. */
    public enum SendOptions {
        /** A real email: rate caps, retries, bounce marking and failure audit. */
        TRANSACTIONAL(true, true),
        /** The admin test endpoint: rate caps and one synchronous attempt only (no retry, no bounce marking). */
        TEST(false, false);

        private final boolean retry;
        private final boolean track;

        SendOptions(final boolean retry, final boolean track) {
            this.retry = retry;
            this.track = track;
        }
    }

    private static final Logger LOG = LogManager.getLogger(EmailOutbox.class);
    private static final String SYSTEM = "system";
    private static final String NO_REALM = "(global)";

    private final EmailDelivery delivery;
    private final EmailRetryStore store;
    private final EmailSendRateCap rateCap;
    private final BounceRecorder bounces;
    private final EmailProperties.Retry retry;
    private final HelixMetrics metrics;
    private final AuditLog audit;
    private final Clock clock;
    private final AtomicLong queued = new AtomicLong();
    private final Map<String, Long> capAuditedMinute = new ConcurrentHashMap<>();

    /**
     * @param store   where retries wait; null: no retries
     * @param rateCap the send rate caps; null: none
     * @param bounces marks bounced addresses; null: bounces are only audited
     */
    public EmailOutbox(final EmailDelivery delivery, final EmailRetryStore store, final EmailSendRateCap rateCap,
                       final BounceRecorder bounces, final EmailProperties properties, final HelixMetrics metrics,
                       final AuditLog audit, final Clock clock) {
        this.delivery = delivery;
        this.store = store;
        this.rateCap = rateCap;
        this.bounces = bounces;
        this.retry = properties == null ? new EmailProperties.Retry() : properties.getRetry();
        this.metrics = metrics;
        this.audit = audit;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        if (metrics != null && store != null) {
            metrics.registerEmailRetryQueueGauge(queued::get);
        }
    }

    /** An outbox that only makes the synchronous attempt: no rate cap, retries or bounce marking (tests, fallbacks). */
    public static EmailOutbox direct(final EmailDelivery delivery) {
        return new EmailOutbox(delivery, null, null, null, null, null, null, null);
    }

    /** The realm's enabled email provider (see {@link EmailDelivery#realmProvider}). */
    public Optional<ResolvedProviderDto> realmProvider(final String realm) {
        return delivery.realmProvider(realm);
    }

    /** Sends {@code message} for {@code realm} (null: outside a realm); see the class description. Never throws. */
    public EmailSendOutcome send(final String realm, final EmailMessage message, final SendOptions options) {
        final Optional<EmailSendOutcome> capped = checkRateCap(realm);
        if (capped.isPresent()) {
            return capped.get();
        }
        final Instant firstAttempt = clock.instant();
        final DeliveryResult result = delivery.deliver(realm, message);
        if (!options.track) {
            return new EmailSendOutcome(result, false);
        }
        if (result.isSuccess()) {
            return new EmailSendOutcome(result, false);
        }
        if (!result.isRetryable() || result.reason() == Reason.NO_PROVIDER) {
            permanentFailure(realm, message, result, 1, "first-attempt");
            return new EmailSendOutcome(result, false);
        }
        if (!options.retry || !retry.isEnabled() || store == null) {
            sendFailed(realm, message, result, 1, "first-attempt");
            return new EmailSendOutcome(result, false);
        }
        final Instant giveUpAt = firstAttempt.plus(retry.getMaxAge());
        final Instant next = nextAttempt(1, clock.instant());
        if (next == null || !next.isBefore(giveUpAt)) {
            sendFailed(realm, message, result, 1, "gave-up");
            return new EmailSendOutcome(result, false);
        }
        if (message.expiresAt() != null && !next.isBefore(message.expiresAt())) {
            sendFailed(realm, message, result, 1, "expired");
            return new EmailSendOutcome(result, false);
        }
        try {
            store.insert(new EmailRetryStore.Entry(realm, message, 1, firstAttempt, next, giveUpAt,
                    result.reason().name()));
        } catch (final RuntimeException e) {
            LOG.warn("Could not queue email {} of realm {} for a retry: {}", LogSafe.sanitize(message.messageId()),
                    LogSafe.sanitize(realm), LogSafe.sanitize(e.getClass().getSimpleName()));
            sendFailed(realm, message, result, 1, "first-attempt");
            return new EmailSendOutcome(result, false);
        }
        queued.incrementAndGet();
        recordRetry(realm, "scheduled");
        LOG.info("Email {} of realm {} queued for a retry at {} ({})", LogSafe.sanitize(message.messageId()),
                LogSafe.sanitize(realm), next, result.reason());
        return new EmailSendOutcome(result, true);
    }

    /**
     * Sends the retries that are due (one batch), then refreshes the queue gauge. Returns how many were attempted or
     * finished. Called by {@link EmailRetryWorker} on every replica; safe to call concurrently.
     */
    public int processDue() {
        if (store == null) {
            return 0;
        }
        final String claimToken = UUID.randomUUID().toString();
        final List<EmailRetryStore.Entry> due = store.claim(clock.instant(), retry.getLease(),
                Math.max(1, retry.getBatchSize()), claimToken);
        for (final EmailRetryStore.Entry entry : due) {
            try {
                retry(entry, claimToken);
            } catch (final RuntimeException e) {
                // The claim runs out and another poll tries again.
                LOG.warn("Retry of email {} failed: {}", LogSafe.sanitize(entry.messageId()),
                        LogSafe.sanitize(e.getClass().getSimpleName()));
            }
        }
        refreshQueueGauge();
        return due.size();
    }

    /** Re-reads how many emails wait for a retry, for {@code helix_email_retry_queued}. */
    public void refreshQueueGauge() {
        if (store == null) {
            return;
        }
        try {
            queued.set(store.count());
        } catch (final RuntimeException e) {
            LOG.debug("Could not count the email retry queue", e);
        }
    }

    private void retry(final EmailRetryStore.Entry entry, final String claimToken) {
        final String realm = entry.realm();
        final EmailMessage message = entry.message();
        final Instant now = clock.instant();
        if (message.isExpiredAt(now)) {
            if (store.delete(entry.messageId(), claimToken)) {
                recordRetry(realm, "expired");
                sendFailed(realm, message, DeliveryResult.transientFailure(reasonOf(entry.lastReason()), null),
                        entry.attempts(), "expired");
            }
            return;
        }
        if (!now.isBefore(entry.giveUpAt())) {
            if (store.delete(entry.messageId(), claimToken)) {
                recordRetry(realm, "gave_up");
                sendFailed(realm, message, DeliveryResult.transientFailure(reasonOf(entry.lastReason()), null),
                        entry.attempts(), "gave-up");
            }
            return;
        }
        final int attempts = entry.attempts() + 1;
        final DeliveryResult result = delivery.deliver(realm, message);
        if (result.isSuccess()) {
            if (store.delete(entry.messageId(), claimToken)) {
                recordRetry(realm, "delivered");
            }
            return;
        }
        if (!result.isRetryable() || result.reason() == Reason.NO_PROVIDER) {
            if (store.delete(entry.messageId(), claimToken)) {
                recordRetry(realm, "permanent");
            }
            permanentFailure(realm, message, result, attempts, "retry");
            return;
        }
        final Instant next = nextAttempt(attempts, clock.instant());
        final String stage = next == null || !next.isBefore(entry.giveUpAt()) ? "gave-up"
                : message.expiresAt() != null && !next.isBefore(message.expiresAt()) ? "expired" : null;
        if (stage != null) {
            if (store.delete(entry.messageId(), claimToken)) {
                recordRetry(realm, "expired".equals(stage) ? "expired" : "gave_up");
                sendFailed(realm, message, result, attempts, stage);
            }
            return;
        }
        if (store.reschedule(entry.messageId(), claimToken, attempts, next, result.reason().name())) {
            recordRetry(realm, "rescheduled");
        }
    }

    /**
     * When attempt {@code attempts + 1} is due, from {@code now}: the configured delay after attempt {@code attempts},
     * spread by the jitter; null when no delay is left.
     */
    private Instant nextAttempt(final int attempts, final Instant now) {
        final List<Duration> delays = retry.getDelays();
        if (delays == null || attempts < 1 || attempts > delays.size()) {
            return null;
        }
        final long base = delays.get(attempts - 1).toMillis();
        final double jitter = Math.max(0, Math.min(1, retry.getJitter()));
        final double factor = jitter == 0 ? 1 : 1 + ThreadLocalRandom.current().nextDouble(-jitter, jitter);
        return now.plusMillis(Math.max(1_000L, Math.round(base * factor)));
    }

    private Optional<EmailSendOutcome> checkRateCap(final String realm) {
        if (rateCap == null) {
            return Optional.empty();
        }
        final EmailSendRateCap.Decision decision = rateCap.tryAcquire(realm, realmLimit(realm));
        if (decision.allowed()) {
            return Optional.empty();
        }
        final String scope = decision.scope() == EmailSendRateCap.Scope.GLOBAL ? "global" : "realm";
        final String diagnostic = "global".equals(scope)
                ? "The server's send rate cap (" + decision.limitPerMinute() + " emails per minute) is reached"
                : "The realm's send rate cap (" + decision.limitPerMinute() + " emails per minute) is reached";
        if (metrics != null) {
            metrics.recordEmailRateCapped(realm, scope);
        }
        final long minute = clock.millis() / 60_000L;
        final String key = (realm == null ? NO_REALM : realm) + "|" + scope;
        final Long previous = capAuditedMinute.put(key, minute);
        if (previous == null || previous != minute) {
            if (capAuditedMinute.size() > 10_000) {
                capAuditedMinute.clear();
            }
            LOG.warn("Email of realm {} refused: {}", LogSafe.sanitize(realm), diagnostic);
            final Map<String, String> detail = new LinkedHashMap<>();
            detail.put("scope", scope);
            detail.put("limitPerMinute", String.valueOf(decision.limitPerMinute()));
            emit("EMAIL_SEND_RATE_CAPPED", realm, "email", "rate-cap", detail);
        }
        return Optional.of(new EmailSendOutcome(DeliveryResult.transientFailure(Reason.RATE_CAPPED, diagnostic),
                false));
    }

    /** The realm's own {@code sendLimitPerMinute} from its email provider settings; null for the default. */
    private Integer realmLimit(final String realm) {
        if (realm == null) {
            return null;
        }
        try {
            return delivery.realmProvider(realm).map(ResolvedProviderDto::config)
                    .map(c -> c.get("sendLimitPerMinute")).map(String::trim).filter(v -> !v.isEmpty())
                    .map(Integer::valueOf).orElse(null);
        } catch (final RuntimeException e) {
            return null;
        }
    }

    private void permanentFailure(final String realm, final EmailMessage message, final DeliveryResult result,
                                  final int attempts, final String stage) {
        if (result.reason() == Reason.RECIPIENT_BOUNCED) {
            bounced(realm, message, result);
            return;
        }
        if (result.reason() == Reason.NO_PROVIDER) {
            return; // logged by the caller; nothing was attempted
        }
        sendFailed(realm, message, result, attempts, stage);
    }

    private void bounced(final String realm, final EmailMessage message, final DeliveryResult result) {
        if (metrics != null) {
            metrics.recordEmailBounce(realm);
        }
        final List<String> addresses = result.bouncedRecipients().isEmpty()
                ? message.to().stream().map(EmailAddress::address).toList() : result.bouncedRecipients();
        boolean audited = false;
        for (final String address : addresses) {
            List<String> users = List.of();
            if (bounces != null) {
                try {
                    users = bounces.markBounced(realm, address, clock.instant());
                } catch (final RuntimeException e) {
                    LOG.warn("Could not mark a bounced address in realm {}: {}", LogSafe.sanitize(realm),
                            LogSafe.sanitize(e.getClass().getSimpleName()));
                }
            }
            for (final String userId : users) {
                emit("EMAIL_BOUNCED", realm, "user", userId, failureDetail(message, result, 0, null));
                audited = true;
            }
        }
        if (!audited) {
            emit("EMAIL_BOUNCED", realm, "email", message.messageId(), failureDetail(message, result, 0, null));
        }
        LOG.warn("Email {} of realm {} bounced: the recipient's address does not accept mail ({})",
                LogSafe.sanitize(message.messageId()), LogSafe.sanitize(realm), LogSafe.sanitize(result.diagnostic()));
    }

    private void sendFailed(final String realm, final EmailMessage message, final DeliveryResult result,
                            final int attempts, final String stage) {
        LOG.warn("Email {} of realm {} not delivered after {} attempt(s) ({}): {} {}",
                LogSafe.sanitize(message.messageId()), LogSafe.sanitize(realm), attempts, stage, result.status(),
                result.reason());
        emit("EMAIL_SEND_FAILED", realm, "email", message.messageId(), failureDetail(message, result, attempts, stage));
    }

    /** The audit detail of a failure: status, reason, diagnostic, attempts and stage; never the body or recipient. */
    private static Map<String, String> failureDetail(final EmailMessage message, final DeliveryResult result,
                                                     final int attempts, final String stage) {
        final Map<String, String> detail = new LinkedHashMap<>();
        detail.put("messageId", message.messageId());
        detail.put("status", result.status().name());
        detail.put("reason", result.reason().name());
        if (result.diagnostic() != null) {
            detail.put("diagnostic", result.diagnostic());
        }
        if (attempts > 0) {
            detail.put("attempts", String.valueOf(attempts));
        }
        if (stage != null) {
            detail.put("stage", stage);
        }
        return detail;
    }

    private void emit(final String type, final String realm, final String resourceType, final String resourceId,
                      final Map<String, String> detail) {
        if (audit == null) {
            return;
        }
        try {
            audit.emit(AuditEvent.admin(AuditContext.nowIso(), type, realm == null ? NO_REALM : realm, SYSTEM, null,
                    resourceType, resourceId, "FAILURE", detail));
        } catch (final RuntimeException e) {
            LOG.debug("Audit of {} failed", type, e);
        }
    }

    private void recordRetry(final String realm, final String outcome) {
        if (metrics != null) {
            metrics.recordEmailRetry(realm, outcome);
        }
    }

    private static Reason reasonOf(final String name) {
        try {
            return name == null ? Reason.PROVIDER_ERROR : Reason.valueOf(name);
        } catch (final IllegalArgumentException e) {
            return Reason.PROVIDER_ERROR;
        }
    }
}
