/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.e2e.browser;

import io.helixiam.authorization.amqp.messaging.ResolvedProviderDto;
import io.helixiam.authorization.messaging.driver.CloudflareEmailDriver;
import io.helixiam.authorization.messaging.email.DeliveryResult;
import io.helixiam.authorization.messaging.email.DeliveryResult.Status;
import io.helixiam.authorization.messaging.email.EmailDelivery;
import io.helixiam.authorization.messaging.email.EmailMessage;
import io.helixiam.authorization.messaging.email.EmailOutbox;
import io.helixiam.authorization.messaging.email.EmailProperties;
import io.helixiam.authorization.messaging.email.EmailRetryStore;
import io.helixiam.authorization.messaging.email.EmailSendOutcome;
import io.helixiam.authorization.messaging.email.EmailTransport;
import io.helixiam.authorization.messaging.email.JdbcEmailRetryStore;
import io.helixiam.authorization.messaging.email.MutableClock;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.persistence.security.AttributeEncryption;
import io.helixiam.testsupport.CloudflareApiMock;
import io.helixiam.testsupport.TestTls;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The persisted email retry queue on the real database (both schema paths: Flyway V72 and {@code schema.sql}): a
 * retry survives a restart (a new store and outbox, sharing nothing but the table, deliver it), the stored message is
 * encrypted at rest, two workers never send the same retry, and a claim whose worker died is taken over.
 *
 * <p>The shared server runs its own retry worker on the same table with the real clock. These tests run their own
 * store and outbox instances on a clock a century ahead, so every row they write is not yet due for the server's
 * worker, and each test only touches its own message ids.
 */
class EmailRetryQueueE2eTest extends AbstractE2eTest {

    private static final String KEY = "0123456789abcdef0123456789abcdef";
    private static final Instant FUTURE = Instant.parse("2126-01-01T00:00:00Z");
    private static final String LINK = "https://idp.example.com/login/magic/verify?token=retry-e2e-secret-token";

    private static TestTls tls;
    private static CloudflareApiMock cloudflare;

    @BeforeAll
    static void startMock() {
        tls = TestTls.create("email-retry-e2e");
        cloudflare = CloudflareApiMock.https(tls);
    }

    @AfterAll
    static void stopMock() {
        cloudflare.close();
    }

    private JdbcTemplate jdbc() {
        return context.getBean(JdbcTemplate.class);
    }

    /** A fresh store, as a restarted server (or another replica) builds it: nothing shared but the table. */
    private JdbcEmailRetryStore newStore() {
        return new JdbcEmailRetryStore(jdbc(), context.getBean(PlatformTransactionManager.class),
                new AttributeEncryption(KEY));
    }

    private static EmailProperties noJitter() {
        final EmailProperties props = new EmailProperties();
        props.getRetry().setJitter(0);
        return props;
    }

    private static ResolvedProviderDto cloudflareProvider() {
        return new ResolvedProviderDto("EMAIL", "CLOUDFLARE", "no-reply@acme.example.com", "Acme",
                Map.of("accountId", "acme0123456789", "baseUrl", cloudflare.baseUrl(), "caBundle", tls.caPem(),
                        "readTimeoutMs", "5000"), "cf-retry-token");
    }

    private static EmailOutbox cloudflareOutbox(final EmailRetryStore store, final MutableClock clock) {
        final EmailDelivery delivery = new EmailDelivery(realm -> List.of(cloudflareProvider()),
                List.of(new CloudflareEmailDriver(OutboundUrlGuard.permissive(), DeploymentProfile.production())), null,
                null, null);
        return new EmailOutbox(delivery, store, null, null, noJitter(), null, null, clock);
    }

    @Test
    void aTransientFailure_isPersisted_encrypted_andDeliveredAfterARestart_withTheSameMessage() {
        final String to = "retry-" + System.nanoTime() + "@example.org";
        final AtomicInteger calls = new AtomicInteger();
        cloudflare.respond(r -> to.equals(r.to()) && calls.incrementAndGet() == 1
                ? CloudflareApiMock.Response.of(503, "{\"success\":false,\"errors\":[{\"code\":10500,"
                + "\"message\":\"Service unavailable\"}]}")
                : CloudflareApiMock.delivered(r.to()));
        final MutableClock clock = new MutableClock(FUTURE);
        final EmailMessage message = EmailMessage.of(null, to, "Sign in to Acme",
                "<p><a href=\"" + LINK + "\">Sign in</a></p>", true, null)
                .withExpiresAt(FUTURE.plus(Duration.ofMinutes(15)));

        final EmailSendOutcome outcome = cloudflareOutbox(newStore(), clock).send("acme", message,
                EmailOutbox.SendOptions.TRANSACTIONAL);

        assertThat(outcome.result().status()).isEqualTo(Status.TRANSIENT_FAILURE);
        assertThat(outcome.retryScheduled()).isTrue();
        final Map<String, Object> row = jdbc().queryForMap("SELECT * FROM email_retry WHERE message_id = ?",
                message.messageId());
        assertThat(row.get("realm_id")).isEqualTo("acme");
        assertThat(((Number) row.get("attempts")).intValue()).isEqualTo(1);
        assertThat(((Number) row.get("expires_at")).longValue()).isEqualTo(message.expiresAt().toEpochMilli());
        assertThat(row.get("last_reason")).isEqualTo("PROVIDER_ERROR");
        // The body carries a live sign-in link: encrypted at rest, like every other secret column.
        assertThat(String.valueOf(row.get("payload"))).doesNotContain(LINK).doesNotContain("retry-e2e-secret-token")
                .doesNotContain("Sign in to Acme").doesNotContain(to);

        // "Restart": a new store and outbox, sharing nothing with the first but the table.
        clock.advance(Duration.ofSeconds(30));
        final EmailOutbox restarted = cloudflareOutbox(newStore(), clock);
        assertThat(restarted.processDue()).isEqualTo(1);

        assertThat(jdbc().queryForObject("SELECT count(*) FROM email_retry WHERE message_id = ?", Long.class,
                message.messageId())).isZero();
        final List<CloudflareApiMock.Request> sent = cloudflare.requests().stream()
                .filter(r -> to.equals(r.to())).toList();
        assertThat(sent).hasSize(2);
        assertThat(sent.get(1).body()).isEqualTo(sent.get(0).body()); // the same rendered message, link included
        assertThat(sent.get(1).json().path("html").asText()).contains(LINK);
        assertThat(sent.get(1).json().path("text").asText()).contains(LINK);
        assertThat(sent.get(1).json().path("subject").asText()).isEqualTo("Sign in to Acme");
    }

    @Test
    void anExpiredCode_isNotSentAgain_afterARestart() {
        final String to = "expired-" + System.nanoTime() + "@example.org";
        cloudflare.respond(r -> CloudflareApiMock.Response.of(503, "{\"success\":false,\"errors\":[]}"));
        final MutableClock clock = new MutableClock(FUTURE);
        final EmailMessage otp = EmailMessage.of(null, to, "Your code", "Your code is 481516", false, null)
                .withExpiresAt(FUTURE.plus(Duration.ofMinutes(5)));
        assertThat(cloudflareOutbox(newStore(), clock).send("acme", otp, EmailOutbox.SendOptions.TRANSACTIONAL)
                .retryScheduled()).isTrue();

        clock.advance(Duration.ofMinutes(6)); // the server was down past the code's expiry
        cloudflare.respond(r -> CloudflareApiMock.delivered(r.to()));
        cloudflareOutbox(newStore(), clock).processDue();

        assertThat(cloudflare.requests().stream().filter(r -> to.equals(r.to()))).hasSize(1);
        assertThat(jdbc().queryForObject("SELECT count(*) FROM email_retry WHERE message_id = ?", Long.class,
                otp.messageId())).isZero();
    }

    /** A transport that records which message ids it sent, with a small delay so the workers overlap. */
    private static final class Recording implements EmailTransport {
        final Map<String, AtomicInteger> sends = new ConcurrentHashMap<>();

        @Override
        public String driver() {
            return "RECORDING";
        }

        @Override
        public DeliveryResult deliver(final ResolvedProviderDto provider, final EmailMessage message) {
            sends.computeIfAbsent(message.messageId(), k -> new AtomicInteger()).incrementAndGet();
            try {
                Thread.sleep(2);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DeliveryResult.accepted(null, null);
        }
    }

    @Test
    void twoWorkers_neverSendTheSameRetry() throws Exception {
        final MutableClock clock = new MutableClock(FUTURE.plus(Duration.ofDays(1)));
        final String realm = "concurrency-" + System.nanoTime();
        final JdbcEmailRetryStore seedStore = newStore();
        final Set<String> ids = new HashSet<>();
        for (int i = 0; i < 60; i++) {
            final EmailMessage m = EmailMessage.of(null, "user" + i + "@example.org", "Hi", "Hello", false, null);
            ids.add(m.messageId());
            seedStore.insert(new EmailRetryStore.Entry(realm, m, 1, clock.instant(), clock.instant(),
                    clock.instant().plus(Duration.ofHours(1)), "NETWORK"));
        }
        final Recording transport = new Recording();
        final EmailProperties props = noJitter();
        props.getRetry().setBatchSize(4);
        final ResolvedProviderDto provider = new ResolvedProviderDto("EMAIL", "RECORDING", "no-reply@acme.example.com",
                null, Map.of(), null);
        final List<EmailOutbox> workers = new ArrayList<>();
        for (int w = 0; w < 2; w++) {
            final EmailDelivery delivery = new EmailDelivery(r -> List.of(provider), List.of(transport), null, null,
                    null);
            workers.add(new EmailOutbox(delivery, newStore(), null, null, props, null, null, clock));
        }

        final ExecutorService pool = Executors.newFixedThreadPool(2);
        final CountDownLatch go = new CountDownLatch(1);
        try {
            final List<Future<Integer>> runs = new ArrayList<>();
            for (final EmailOutbox worker : workers) {
                runs.add(pool.submit(() -> {
                    go.await();
                    int claimed = 0;
                    int n;
                    while ((n = worker.processDue()) > 0) {
                        claimed += n;
                    }
                    return claimed;
                }));
            }
            go.countDown();
            final int total = runs.get(0).get() + runs.get(1).get();

            assertThat(total).isEqualTo(60);
            assertThat(runs.get(0).get()).isPositive(); // both workers took part
            assertThat(runs.get(1).get()).isPositive();
        } finally {
            pool.shutdownNow();
        }
        assertThat(transport.sends.keySet()).isEqualTo(ids);
        assertThat(transport.sends.values()).allSatisfy(count -> assertThat(count.get()).isEqualTo(1));
        assertThat(jdbc().queryForObject("SELECT count(*) FROM email_retry WHERE realm_id = ?", Long.class, realm))
                .isZero();
    }

    @Test
    void concurrentClaims_returnDisjointRows() throws Exception {
        final Instant now = FUTURE.plus(Duration.ofDays(2));
        final String realm = "claims-" + System.nanoTime();
        final JdbcEmailRetryStore seedStore = newStore();
        for (int i = 0; i < 40; i++) {
            seedStore.insert(new EmailRetryStore.Entry(realm, EmailMessage.of(null, "c" + i + "@example.org", "Hi",
                    "x", false, null), 1, now, now, now.plus(Duration.ofHours(1)), "NETWORK"));
        }
        final int threads = 4;
        final ExecutorService pool = Executors.newFixedThreadPool(threads);
        final CountDownLatch go = new CountDownLatch(1);
        final List<String> claimed = Collections.synchronizedList(new ArrayList<>());
        try {
            final List<Future<?>> runs = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                final JdbcEmailRetryStore store = newStore();
                final String token = "worker-" + t;
                runs.add(pool.submit(() -> {
                    go.await();
                    List<EmailRetryStore.Entry> batch;
                    while (!(batch = store.claim(now, Duration.ofMinutes(2), 3, token)).isEmpty()) {
                        batch.forEach(e -> claimed.add(e.messageId()));
                    }
                    return null;
                }));
            }
            go.countDown();
            for (final Future<?> run : runs) {
                run.get();
            }
        } finally {
            pool.shutdownNow();
        }
        final List<String> ours = claimed.stream().filter(id -> jdbc().queryForObject(
                "SELECT count(*) FROM email_retry WHERE message_id = ? AND realm_id = ?", Long.class, id, realm) == 1)
                .toList();
        assertThat(ours).hasSize(40).doesNotHaveDuplicates();
        // The pool runs with auto-commit off: clean up in a transaction.
        new org.springframework.transaction.support.TransactionTemplate(
                context.getBean(PlatformTransactionManager.class)).executeWithoutResult(s ->
                jdbc().update("DELETE FROM email_retry WHERE realm_id = ?", realm));
    }

    @Test
    void aClaimWhoseWorkerDied_isTakenOverAfterTheLease_andTheOldWorkerCanNoLongerFinishIt() {
        final Instant now = FUTURE.plus(Duration.ofDays(3));
        final JdbcEmailRetryStore store = newStore();
        final EmailMessage m = EmailMessage.of(null, "lease@example.org", "Hi", "x", false, null);
        store.insert(new EmailRetryStore.Entry("lease-" + System.nanoTime(), m, 1, now, now,
                now.plus(Duration.ofHours(1)), "NETWORK"));

        assertThat(store.claim(now, Duration.ofMinutes(2), 10, "dead-worker"))
                .extracting(EmailRetryStore.Entry::messageId).contains(m.messageId());
        assertThat(newStore().claim(now.plus(Duration.ofMinutes(1)), Duration.ofMinutes(2), 10, "other"))
                .extracting(EmailRetryStore.Entry::messageId).doesNotContain(m.messageId());
        assertThat(newStore().claim(now.plus(Duration.ofMinutes(2)), Duration.ofMinutes(2), 10, "other"))
                .extracting(EmailRetryStore.Entry::messageId).contains(m.messageId());

        assertThat(store.delete(m.messageId(), "dead-worker")).isFalse();
        assertThat(store.reschedule(m.messageId(), "dead-worker", 2, now, "NETWORK")).isFalse();
        assertThat(store.delete(m.messageId(), "other")).isTrue();
    }
}
