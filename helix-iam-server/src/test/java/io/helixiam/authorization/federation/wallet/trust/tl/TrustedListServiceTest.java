/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.Service;
import io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.Spec;
import io.helixiam.authorization.messaging.email.MutableClock;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.testcontainers.containers.PostgreSQLContainer;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.PID_TYPE;
import static io.helixiam.authorization.federation.wallet.trust.tl.TrustedListFixtures.WITHDRAWN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link TrustedListService} on a real PostgreSQL (the Flyway schema): refresh, the fail-safe grace rule, expiry,
 * withdrawal, rollback, audit, settings changes, and two replicas sharing one database (one refresh, both converge).
 */
class TrustedListServiceTest {

    @SuppressWarnings("resource")
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");
    static final HikariDataSource DATA_SOURCE;
    static final JdbcTemplate JDBC;
    static final DataSourceTransactionManager TRANSACTIONS;

    static {
        POSTGRES.start();
        final HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(8);
        config.setAutoCommit(false);
        DATA_SOURCE = new HikariDataSource(config);
        Flyway.configure().dataSource(DATA_SOURCE).locations("classpath:db/migration").load().migrate();
        JDBC = new JdbcTemplate(DATA_SOURCE);
        TRANSACTIONS = new DataSourceTransactionManager(DATA_SOURCE);
    }

    @AfterAll
    static void close() {
        DATA_SOURCE.close();
    }

    static final String URL = "https://tl.example/TL/UT.xml";
    final TestPki.Leaf signer = TrustedListFixtures.signer("UT TL Signer");
    final X509Certificate issuer = TestPki.create("Listed PID Issuer").root();
    final Map<String, byte[]> served = new ConcurrentHashMap<>();
    final AtomicInteger fetches = new AtomicInteger();
    final MutableClock clock = new MutableClock(Instant.now());
    final List<String> audits = new CopyOnWriteArrayList<>();
    final List<Map<String, String>> auditDetails = new CopyOnWriteArrayList<>();
    final TrustedListFetcher fetcher = (url, realm) -> {
        fetches.incrementAndGet();
        final byte[] b = served.get(url);
        if (b == null) {
            throw new TrustedListException(TrustedListException.Kind.FETCH, "the list URL answered HTTP 404");
        }
        return b;
    };
    String realm;
    TrustedListService service;

    @BeforeEach
    void setUp() {
        realm = "tl-" + UUID.randomUUID();
        service = newReplica(fetcher);
    }

    TrustedListService newReplica(final TrustedListFetcher f) {
        return newReplica(f, TrustedListService.Settings.DEFAULTS);
    }

    TrustedListService newReplica(final TrustedListFetcher f, final TrustedListService.Settings settings) {
        return new TrustedListService(new TrustedListRepository(JDBC, TRANSACTIONS),
                new TrustedListLoader(f, clock), (r, type, id, outcome, detail) -> {
                    if (realm.equals(r)) {
                        audits.add(type + ":" + outcome);
                        auditDetails.add(detail);
                    }
                }, clock, settings, INTEGRITY, false);
    }

    static final TrustedListIntegrity INTEGRITY = TrustedListIntegrity.fromSecret("0123456789abcdef0123456789abcdef");

    TrustedListSource.Config config(final String name) {
        return new TrustedListSource.Config(name, URL, TrustedListSpec.Format.ETSI_119612_XML,
                TestPki.pem(signer.certificate()), List.of(PID_TYPE), List.of(), List.of(), 24, true);
    }

    void serve(final Spec spec) {
        served.put(URL, TrustedListFixtures.signedXml(spec, signer));
    }

    Spec listWith(final long sequence, final Service... services) {
        final Spec spec = Spec.memberState("UT").sequence(sequence).issued(clock.instant().minus(1, ChronoUnit.HOURS))
                .nextUpdate(clock.instant().plus(30, ChronoUnit.DAYS));
        for (final Service s : services) {
            spec.service(s);
        }
        return spec;
    }

    /** The config_version a client would hold after reading the source now. */
    long cv(final TrustedListSource source) {
        return new TrustedListRepository(JDBC, TRANSACTIONS).byId(source.id()).orElseThrow().state().configVersion();
    }

    List<X509Certificate> anchors(final TrustedListService s) {
        return s.anchors(realm, List.of("ut"), List.of());
    }

    @Test
    void refresh_storesTheVerifiedAnchors_andAuditsIt() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        assertThat(service.status(created)).isEqualTo(TrustedListHealth.Status.NEVER);
        assertThat(anchors(service)).isEmpty();

        final TrustedListSource after = service.refreshNow(realm, created.id()).orElseThrow();

        assertThat(service.status(after)).isEqualTo(TrustedListHealth.Status.OK);
        assertThat(after.state().sequenceNumber()).isEqualTo(3);
        assertThat(after.state().nextRefreshAt()).isGreaterThan(clock.millis());
        assertThat(anchors(service)).containsExactly(issuer);
        assertThat(service.services(after)).singleElement()
                .satisfies(s -> assertThat(s.provider()).isEqualTo("Issuer"));
        assertThat(audits).containsExactly("TRUSTED_LIST_REFRESHED:SUCCESS");
        assertThat(auditDetails.get(0)).containsEntry("anchors", "1").containsEntry("sequence", "3");
    }

    @Test
    void failedRefresh_keepsTheLastGoodAnchors_untilNextUpdatePlusGrace_thenFailsClosed() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());

        // the publisher now serves a list that does not verify
        served.put(URL, new String(served.get(URL), StandardCharsets.UTF_8).replace("Issuer PID", "Evil PID")
                .getBytes(StandardCharsets.UTF_8));
        final TrustedListSource failing = service.refreshNow(realm, created.id()).orElseThrow();
        assertThat(service.status(failing)).isEqualTo(TrustedListHealth.Status.FAILING);
        assertThat(failing.state().lastError()).startsWith("SIGNATURE:");
        assertThat(anchors(service)).as("unverifiable: last good kept").containsExactly(issuer);
        assertThat(audits).contains("TRUSTED_LIST_REFRESH_FAILED:FAILURE");
        assertThat(auditDetails.get(auditDetails.size() - 1)).containsEntry("reason", "SIGNATURE")
                .containsKey("anchorsKeptUntil");

        // past NextUpdate, within the 24 h grace: still used, STALE recorded once
        clock.advance(Duration.ofDays(30).plusHours(1));
        assertThat(anchors(service)).as("stale within grace").containsExactly(issuer);
        service.checkHealth();
        service.checkHealth();
        assertThat(audits.stream().filter(a -> a.startsWith("TRUSTED_LIST_STALE"))).hasSize(1);
        assertThat(service.status(service.get(realm, created.id()).orElseThrow()))
                .isEqualTo(TrustedListHealth.Status.STALE);

        // past the grace: nothing (fail closed), EXPIRED audited once
        clock.advance(Duration.ofHours(24));
        assertThat(anchors(service)).as("beyond grace").isEmpty();
        service.checkHealth();
        service.checkHealth();
        assertThat(audits.stream().filter(a -> a.startsWith("TRUSTED_LIST_EXPIRED"))).hasSize(1);
        assertThat(service.status(service.get(realm, created.id()).orElseThrow()))
                .isEqualTo(TrustedListHealth.Status.EXPIRED);

        // a fresh, verified list restores it
        serve(listWith(4, Service.granted("Issuer", issuer)));
        assertThat(service.status(service.refreshNow(realm, created.id()).orElseThrow()))
                .isEqualTo(TrustedListHealth.Status.OK);
        assertThat(anchors(service)).containsExactly(issuer);
    }

    @Test
    void neverLoaded_andFailing_hasNoAnchors() {
        final TrustedListSource created = service.create(realm, config("ut")); // nothing served
        final TrustedListSource after = service.refreshNow(realm, created.id()).orElseThrow();

        assertThat(service.status(after)).isEqualTo(TrustedListHealth.Status.ERROR);
        assertThat(after.state().lastError()).contains("404");
        assertThat(anchors(service)).isEmpty();
    }

    @Test
    void withdrawnService_disappearsAtTheNextRefresh() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        assertThat(anchors(service)).containsExactly(issuer);

        serve(listWith(4, Service.granted("Issuer", issuer).withStatus(WITHDRAWN)));
        service.refreshNow(realm, created.id());

        assertThat(anchors(service)).isEmpty();
    }

    @Test
    void olderList_isRefusedAsRollback_andTheNewerAnchorsStay() {
        serve(listWith(9, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());

        serve(listWith(8));
        final TrustedListSource after = service.refreshNow(realm, created.id()).orElseThrow();

        assertThat(after.state().lastError()).startsWith("ROLLBACK:");
        assertThat(after.state().sequenceNumber()).isEqualTo(9);
        assertThat(anchors(service)).containsExactly(issuer);
    }

    @Test
    void nonCaCertificateOnTheList_isNotAnAnchor_andTypeFilterNarrows() {
        final X509Certificate leaf = TrustedListFixtures.signer("Not a CA").certificate();
        serve(listWith(3, Service.granted("Issuer", issuer),
                Service.granted("Leaf", leaf),
                Service.granted("Other", TestPki.create("Other").root()).withType("http://example/other")));
        final TrustedListSource.Config cfg = new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(signer.certificate()),
                List.of(PID_TYPE, "http://example/other"), List.of(), List.of(), 24, true);
        final TrustedListSource created = service.create(realm, cfg);
        service.refreshNow(realm, created.id());

        assertThat(service.anchors(realm, List.of("ut"), List.of())).hasSize(2).contains(issuer).doesNotContain(leaf);
        assertThat(service.anchors(realm, List.of("ut"), List.of(PID_TYPE))).containsExactly(issuer);
        assertThat(service.anchors(realm, List.of("other-name"), List.of())).isEmpty();
        assertThat(service.anchors("another-realm", List.of("ut"), List.of())).isEmpty();
    }

    @Test
    void changingWhatIsLoaded_dropsTheStoredAnchors_butRenamingDoesNot() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());

        final TrustedListSource.Config graceOnly = new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(signer.certificate()), List.of(PID_TYPE),
                List.of(), List.of(), 48, true);
        service.update(realm, created.id(), graceOnly, cv(created));
        assertThat(anchors(service)).containsExactly(issuer);

        final TrustedListSource.Config otherSigner = new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(TrustedListFixtures.signer("New").certificate()),
                List.of(PID_TYPE), List.of(), List.of(), 48, true);
        final TrustedListSource reset = service.update(realm, created.id(), otherSigner, cv(created)).orElseThrow();
        assertThat(anchors(service)).isEmpty();
        assertThat(service.status(reset)).isEqualTo(TrustedListHealth.Status.NEVER);
    }

    @Test
    void disabledSource_hasNoAnchors() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        final TrustedListSource.Config off = new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(signer.certificate()), List.of(PID_TYPE),
                List.of(), List.of(), 24, false);
        service.update(realm, created.id(), off, cv(created));

        assertThat(anchors(service)).isEmpty();
    }

    @Test
    void invalidSettings_andTakenName_areFieldErrors() {
        service.create(realm, config("ut"));
        assertThatThrownBy(() -> service.create(realm, config("ut")))
                .isInstanceOfSatisfying(TrustedListService.InvalidConfigException.class,
                        e -> assertThat(e.fieldErrors()).containsKey("name"));
        final TrustedListSource.Config bad = new TrustedListSource.Config("bad name", "http://tl.example/x.xml",
                TrustedListSpec.Format.ETSI_119612_XML, "not pem", List.of(), List.of(WITHDRAWN), List.of("nl"), 9999,
                true);
        assertThatThrownBy(() -> service.create(realm, bad))
                .isInstanceOfSatisfying(TrustedListService.InvalidConfigException.class,
                        e -> assertThat(e.fieldErrors()).containsOnlyKeys("name", "url", "signerCertificates",
                                "serviceTypes", "acceptedStatuses", "territories", "graceHours"));
    }

    @Test
    void weakPinnedSignerKey_isAFieldError() {
        final TrustedListSource.Config weak = new TrustedListSource.Config("weak", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(TestPki.caCertificate(TestPki.KeyType.RSA_1024, null)),
                List.of(PID_TYPE), List.of(), List.of(), 24, true);
        assertThatThrownBy(() -> service.create(realm, weak))
                .isInstanceOfSatisfying(TrustedListService.InvalidConfigException.class,
                        e -> assertThat(e.fieldErrors()).containsOnlyKeys("signerCertificates")
                                .extractingByKey("signerCertificates").asString().contains("2048"));
        final TrustedListSource.Config strong = new TrustedListSource.Config("strong", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(TestPki.caCertificate(TestPki.KeyType.RSA_2048, null)),
                List.of(PID_TYPE), List.of(), List.of(), 24, true);
        assertThat(service.create(realm, strong).config().name()).isEqualTo("strong");
    }

    @Test
    void pinnedSignerExpiringSoon_isAuditedOnRefresh() {
        final TestPki.Leaf soon = TrustedListFixtures.signer("Soon", clock.instant().minus(Duration.ofDays(300)),
                clock.instant().plus(Duration.ofDays(10)));
        served.put(URL, TrustedListFixtures.signedXml(listWith(3, Service.granted("Issuer", issuer)), soon));
        final TrustedListSource created = service.create(realm, new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(soon.certificate()), List.of(PID_TYPE), List.of(),
                List.of(), 24, true));

        service.refreshNow(realm, created.id());

        assertThat(audits).contains("TRUSTED_LIST_SIGNER_EXPIRING:FAILURE");
        assertThat(auditDetails.stream().filter(d -> d.containsKey("signerNotAfter"))).singleElement()
                .satisfies(d -> assertThat(d.get("signerSubject")).contains("CN=Soon"));
    }

    @Test
    void deletedSource_isGoneOnEveryReplica() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListService other = newReplica(fetcher);
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        other.sync();
        assertThat(anchors(other)).containsExactly(issuer);

        service.delete(realm, created.id());
        other.sync();

        assertThat(anchors(other)).isEmpty();
        assertThat(other.exists(realm, "ut")).isFalse();
    }

    @Test
    void twoReplicas_refreshOnce_andBothConverge() throws Exception {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final CountDownLatch inFetch = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final TrustedListFetcher slow = (url, r) -> {
            inFetch.countDown();
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return fetcher.fetch(url, r);
        };
        final TrustedListService a = newReplica(slow);
        final TrustedListService b = newReplica(slow);
        a.create(realm, config("ut"));
        final ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            final Future<Integer> first = pool.submit(a::refreshDue);
            assertThat(inFetch.await(10, TimeUnit.SECONDS)).isTrue();
            // b runs while a holds the lease: it must not fetch
            final Future<Integer> second = pool.submit(b::refreshDue);
            final int bRefreshed = second.get(10, TimeUnit.SECONDS);
            release.countDown();
            final int aRefreshed = first.get(10, TimeUnit.SECONDS);
            assertThat(fetches.get()).isEqualTo(1);
            assertThat(new ArrayList<>(List.of(aRefreshed, bRefreshed))).containsExactlyInAnyOrder(1, 0);
        } finally {
            pool.shutdownNow();
        }
        b.sync();
        assertThat(anchors(a)).containsExactly(issuer);
        assertThat(anchors(b)).containsExactly(issuer);
        // and a refresh-now while the lease is held is refused, not run twice
        final TrustedListSource source = a.list(realm).get(0);
        new TrustedListRepository(JDBC, TRANSACTIONS).tryLease(source.id(), "someone-else", clock.millis(),
                clock.millis() + 60_000);
        assertThatThrownBy(() -> b.refreshNow(realm, source.id()))
                .isInstanceOf(TrustedListService.RefreshBusyException.class);
    }

    // ------------------------------------------------------------------------------------------------ races

    /** A fetcher that blocks inside the fetch until released (the review's Race.java). */
    static final class Gate implements TrustedListFetcher {
        final CountDownLatch inFetch = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        final TrustedListFetcher delegate;

        Gate(final TrustedListFetcher delegate) {
            this.delegate = delegate;
        }

        @Override
        public byte[] fetch(final String url, final String realm) throws TrustedListException {
            inFetch.countDown();
            try {
                release.await(20, TimeUnit.SECONDS);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return delegate.fetch(url, realm);
        }
    }

    @Test
    void refreshInFlightWhenTheAdminRepins_isDiscarded_neverStored_neverAuditedAsSuccess() throws Exception {
        // Race.java: the old signer is compromised; a list it signed is being fetched while the admin re-pins
        final TestPki.Leaf oldSigner = TrustedListFixtures.signer("Old (compromised)");
        final TestPki.Leaf newSigner = TrustedListFixtures.signer("New");
        final X509Certificate evil = TestPki.create("Evil Issuer").root();
        served.put(URL, TrustedListFixtures.signedXml(listWith(1000, Service.granted("Evil", evil)), oldSigner));
        final Gate gate = new Gate(fetcher);
        final TrustedListService replica = newReplica(gate);
        final TrustedListSource created = replica.create(realm, new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(oldSigner.certificate()), List.of(PID_TYPE),
                List.of(), List.of(), 24, true));
        final ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            final Future<?> inFlight = pool.submit(() -> replica.refreshNow(realm, created.id()));
            assertThat(gate.inFetch.await(10, TimeUnit.SECONDS)).isTrue();
            replica.update(realm, created.id(), new TrustedListSource.Config("ut", URL,
                    TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(newSigner.certificate()), List.of(PID_TYPE),
                    List.of(), List.of(), 24, true), cv(created));
            gate.release.countDown();
            inFlight.get(20, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
        replica.sync();
        final TrustedListSource now = replica.get(realm, created.id()).orElseThrow();

        assertThat(replica.anchors(realm, List.of("ut"), List.of())).doesNotContain(evil).isEmpty();
        assertThat(now.state().servicesJson()).isNull();
        assertThat(now.state().sequenceNumber()).isNull();
        assertThat(now.config().signerCertificates()).isEqualTo(TestPki.pem(newSigner.certificate()));
        assertThat(replica.status(now)).isEqualTo(TrustedListHealth.Status.NEVER);
        assertThat(audits).doesNotContain("TRUSTED_LIST_REFRESHED:SUCCESS").contains("TRUSTED_LIST_REFRESH_DISCARDED:FAILURE");
        // the re-pinned source is due at once, and its lease is free
        assertThat(now.state().nextRefreshAt()).isNull();
        assertThat(new TrustedListRepository(JDBC, TRANSACTIONS).tryLease(now.id(), "probe", clock.millis(),
                clock.millis() + 1000)).isTrue();
    }

    @Test
    void consoleRefresh_whileTheSchedulerRefreshesOnTheSameReplica_isBusy() throws Exception {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final Gate gate = new Gate(fetcher);
        final TrustedListService replica = newReplica(gate);
        final TrustedListSource created = replica.create(realm, config("ut"));
        final ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            // the first refresh of this source (as the scheduler would run it) holds the lease
            final Future<?> scheduled = pool.submit(() -> replica.refreshNow(realm, created.id()));
            assertThat(gate.inFetch.await(10, TimeUnit.SECONDS)).isTrue();
            assertThatThrownBy(() -> replica.refreshNow(realm, created.id()))
                    .isInstanceOf(TrustedListService.RefreshBusyException.class);
            gate.release.countDown();
            scheduled.get(20, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
        assertThat(fetches.get()).isEqualTo(1);
    }

    @Test
    void leaseIsRenewedWhileALongLoadRuns() throws Exception {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListService.Settings shortLease = new TrustedListService.Settings(Duration.ofHours(6),
                Duration.ofMinutes(15), Duration.ofMillis(900));
        final CountDownLatch inFetch = new CountDownLatch(1);
        final TrustedListFetcher slow = (url, r) -> {
            inFetch.countDown();
            try {
                Thread.sleep(2_500); // longer than the lease
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return fetcher.fetch(url, r);
        };
        // the lease is real time, so this replica runs on the system clock
        final TrustedListService replica = new TrustedListService(new TrustedListRepository(JDBC, TRANSACTIONS),
                new TrustedListLoader(slow, java.time.Clock.systemUTC()), (r, t, i, o, d) -> { },
                java.time.Clock.systemUTC(), shortLease, INTEGRITY, false);
        final TrustedListSource created = replica.create(realm, config("ut"));
        final ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            final Future<?> running = pool.submit(() -> replica.refreshNow(realm, created.id()));
            assertThat(inFetch.await(10, TimeUnit.SECONDS)).isTrue();
            Thread.sleep(1_500); // past the first lease
            assertThat(new TrustedListRepository(JDBC, TRANSACTIONS).tryLease(created.id(), "other-replica",
                    System.currentTimeMillis(), System.currentTimeMillis() + 60_000)).as("lease renewed").isFalse();
            running.get(20, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }
        assertThat(replica.anchors(realm, List.of("ut"), List.of())).containsExactly(issuer);
    }

    @Test
    void lowerSequence_isRefusedBySqlToo() {
        serve(listWith(9, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        final TrustedListRepository repo = new TrustedListRepository(JDBC, TRANSACTIONS);
        final TrustedListSource stored = repo.byId(created.id()).orElseThrow();
        assertThat(repo.tryLease(created.id(), "writer", clock.millis(), clock.millis() + 60_000)).isTrue();

        final boolean written = repo.recordSuccess(created.id(), "writer", stored.state().configVersion(),
                new LoadedList(List.of(), clock.instant(), clock.instant().plus(Duration.ofDays(1)), 4, 1), "[]", null,
                clock.millis(), clock.millis());

        assertThat(written).isFalse();
        assertThat(repo.byId(created.id()).orElseThrow().state().sequenceNumber()).isEqualTo(9);
    }

    @Test
    void staleReplicaHealthCheck_doesNotOverwriteANewerRefresh() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListService a = service;
        final TrustedListService b = newReplica(fetcher);
        final TrustedListSource created = a.create(realm, config("ut"));
        a.refreshNow(realm, created.id());
        b.sync();
        clock.advance(Duration.ofDays(32)); // past NextUpdate + grace for the first list
        serve(listWith(4, Service.granted("Issuer", issuer))); // fresh relative to the new clock
        a.refreshNow(realm, created.id());

        b.checkHealth(); // b still holds the old snapshot until it syncs

        final TrustedListSource now = a.get(realm, created.id()).orElseThrow();
        assertThat(now.state().status()).isEqualTo("OK");
        assertThat(audits).noneMatch(x -> x.startsWith("TRUSTED_LIST_EXPIRED"));
        b.sync();
        assertThat(anchors(b)).containsExactly(issuer);
    }

    // ------------------------------------------------------------------------------------------------ list of lists

    static final String LOTL = "https://lotl.example/lotl.xml";
    static final String NL = "https://tl.example/NL.xml";
    static final String DE = "https://tl.example/DE.xml";
    final TestPki.Leaf lotlSigner = TrustedListFixtures.signer("LOTL Signer");
    final TestPki.Leaf nlSigner = TrustedListFixtures.signer("NL Signer");
    final TestPki.Leaf deSigner = TrustedListFixtures.signer("DE Signer");
    final X509Certificate nlIssuer = TestPki.create("NL PID Issuer").root();
    final X509Certificate deIssuer = TestPki.create("DE PID Issuer").root();

    void serveLotl(final long sequence, final TrustedListFixtures.Pointer... pointers) {
        final Spec spec = Spec.lotl().sequence(sequence).issued(clock.instant().minus(1, ChronoUnit.HOURS))
                .nextUpdate(clock.instant().plus(60, ChronoUnit.DAYS));
        for (final TrustedListFixtures.Pointer p : pointers) {
            spec.pointer(p);
        }
        served.put(LOTL, TrustedListFixtures.signedXml(spec, lotlSigner));
    }

    void serveMember(final String url, final String territory, final long sequence, final int days,
                     final TestPki.Leaf by, final Service... services) {
        final Spec spec = Spec.memberState(territory).sequence(sequence).issued(clock.instant().minus(1, ChronoUnit.HOURS))
                .nextUpdate(clock.instant().plus(days, ChronoUnit.DAYS));
        for (final Service x : services) {
            spec.service(x);
        }
        served.put(url, TrustedListFixtures.signedXml(spec, by));
    }

    TrustedListSource lotlSource() {
        return service.create(realm, new TrustedListSource.Config("ut", LOTL, TrustedListSpec.Format.ETSI_119612_XML,
                TestPki.pem(lotlSigner.certificate()), List.of(PID_TYPE), List.of(), List.of(), 24, true));
    }

    TrustedListSource.Member member(final TrustedListSource source, final String territory) {
        return service.members(service.get(realm, source.id()).orElseThrow()).stream()
                .filter(m -> territory.equals(m.territory())).findFirst().orElseThrow();
    }

    @Test
    void lotl_oneBrokenMember_doesNotBlockTheOthers_andIsReportedAndAudited() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()),
                TrustedListFixtures.Pointer.memberState(DE, "DE", deSigner.certificate()));
        serveMember(NL, "NL", 5, 30, nlSigner, Service.granted("NL", nlIssuer));
        serveMember(DE, "DE", 5, 30, nlSigner, Service.granted("DE", deIssuer)); // wrong signer for DE
        final TrustedListSource created = lotlSource();

        final TrustedListSource after = service.refreshNow(realm, created.id()).orElseThrow();

        assertThat(service.status(after)).isEqualTo(TrustedListHealth.Status.DEGRADED);
        assertThat(anchors(service)).containsExactly(nlIssuer);
        assertThat(member(created, "DE").lastError()).startsWith("SIGNATURE:");
        assertThat(member(created, "NL").lastError()).isNull();
        assertThat(audits).contains("TRUSTED_LIST_REFRESHED:SUCCESS", "TRUSTED_LIST_MEMBER_REFRESH_FAILED:FAILURE");
        assertThat(auditDetails.stream().filter(d -> "DE".equals(d.get("territory")))).singleElement()
                .satisfies(d -> assertThat(d).containsEntry("reason", "SIGNATURE"));
    }

    @Test
    void lotl_memberReplayWithALowerSequence_isRefused_andItsNewerStateStays() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()));
        // sequence 9 withdrew the issuer
        serveMember(NL, "NL", 9, 30, nlSigner, Service.granted("NL", nlIssuer).withStatus(WITHDRAWN));
        final TrustedListSource created = lotlSource();
        service.refreshNow(realm, created.id());
        assertThat(anchors(service)).isEmpty();

        // an attacker replays the older, still-fresh sequence 3 in which the issuer was granted
        serveMember(NL, "NL", 3, 30, nlSigner, Service.granted("NL", nlIssuer));
        service.refreshNow(realm, created.id());

        assertThat(anchors(service)).isEmpty();
        assertThat(member(created, "NL").lastError()).startsWith("ROLLBACK:");
        assertThat(member(created, "NL").sequenceNumber()).isEqualTo(9);
    }

    @Test
    void lotl_memberNearExpiry_expiresAlone() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()),
                TrustedListFixtures.Pointer.memberState(DE, "DE", deSigner.certificate()));
        serveMember(NL, "NL", 5, 5, nlSigner, Service.granted("NL", nlIssuer));
        serveMember(DE, "DE", 5, 30, deSigner, Service.granted("DE", deIssuer));
        final TrustedListSource created = lotlSource();
        service.refreshNow(realm, created.id());
        assertThat(anchors(service)).containsExactlyInAnyOrder(nlIssuer, deIssuer);

        clock.advance(Duration.ofDays(5).plusHours(25)); // past NL's NextUpdate + 24 h grace only
        service.checkHealth();
        service.checkHealth();

        assertThat(anchors(service)).containsExactly(deIssuer);
        assertThat(audits.stream().filter(a -> a.startsWith("TRUSTED_LIST_MEMBER_EXPIRED"))).hasSize(1);
        assertThat(audits).noneMatch(a -> a.startsWith("TRUSTED_LIST_EXPIRED"));
        assertThat(service.status(service.get(realm, created.id()).orElseThrow()))
                .isEqualTo(TrustedListHealth.Status.DEGRADED);
    }

    @Test
    void lotl_failingMemberKeepsItsLastGoodAnchorsUntilItsOwnGraceEnds() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()));
        serveMember(NL, "NL", 5, 30, nlSigner, Service.granted("NL", nlIssuer));
        final TrustedListSource created = lotlSource();
        service.refreshNow(realm, created.id());
        served.remove(NL); // NL's list disappears

        service.refreshNow(realm, created.id());

        assertThat(member(created, "NL").lastError()).startsWith("FETCH:");
        assertThat(anchors(service)).containsExactly(nlIssuer);
        assertThat(auditDetails.stream().filter(d -> "NL".equals(d.get("territory")))).singleElement()
                .satisfies(d -> assertThat(d).containsKey("anchorsKeptUntil").containsEntry("reason", "FETCH"));
    }

    @Test
    void lotl_plainHttpPointer_isSkippedAndReported() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState("http://tl.example/SK.xml", "SK", nlSigner.certificate()),
                TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()));
        serveMember(NL, "NL", 5, 30, nlSigner, Service.granted("NL", nlIssuer));
        final TrustedListSource created = lotlSource();

        final TrustedListSource after = service.refreshNow(realm, created.id()).orElseThrow();

        assertThat(member(created, "SK").lastError()).startsWith("POLICY:");
        assertThat(anchors(service)).containsExactly(nlIssuer);
        assertThat(service.status(after)).isEqualTo(TrustedListHealth.Status.DEGRADED);
    }

    @Test
    void lotl_memberNoLongerPointedAt_isDropped() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()),
                TrustedListFixtures.Pointer.memberState(DE, "DE", deSigner.certificate()));
        serveMember(NL, "NL", 5, 30, nlSigner, Service.granted("NL", nlIssuer));
        serveMember(DE, "DE", 5, 30, deSigner, Service.granted("DE", deIssuer));
        final TrustedListSource created = lotlSource();
        service.refreshNow(realm, created.id());

        serveLotl(11, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()));
        service.refreshNow(realm, created.id());

        assertThat(anchors(service)).containsExactly(nlIssuer);
        assertThat(service.members(service.get(realm, created.id()).orElseThrow()))
                .extracting(TrustedListSource.Member::territory).containsExactly("NL");
    }

    // ------------------------------------------------------------------------------------------------ integrity

    @Test
    void anchorsWrittenIntoTheDatabaseOutsideHelix_areNotUsed_andAudited() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        final X509Certificate evil = TestPki.create("Injected").root();
        final String injected = ServicesCodec.encode(List.of(new ListedService(evil, PID_TYPE, "x", "x", "UT", null)));
        new org.springframework.transaction.support.TransactionTemplate(TRANSACTIONS).executeWithoutResult(t ->
                JDBC.update("UPDATE trusted_list_source SET services_json = ?, version = version + 1 WHERE id = ?",
                        injected, created.id()));

        final TrustedListService other = newReplica(fetcher);
        other.sync();

        assertThat(anchors(other)).isEmpty();
        assertThat(other.services(other.get(realm, created.id()).orElseThrow())).isEmpty();
        assertThat(audits).contains("TRUSTED_LIST_INTEGRITY_FAILED:FAILURE");
    }

    @Test
    void signerPinnedThroughTheDatabase_isRefusedAtRefresh() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        final TestPki.Leaf attacker = TrustedListFixtures.signer("Attacker");
        served.put(URL, TrustedListFixtures.signedXml(listWith(4, Service.granted("Evil", issuer)), attacker));
        new org.springframework.transaction.support.TransactionTemplate(TRANSACTIONS).executeWithoutResult(t ->
                JDBC.update("UPDATE trusted_list_source SET signer_certificates = ? WHERE id = ?",
                        TestPki.pem(attacker.certificate()), created.id()));

        final TrustedListSource after = service.refreshNow(realm, created.id()).orElseThrow();

        assertThat(after.state().lastError()).startsWith("INTEGRITY:");
        assertThat(anchors(service)).isEmpty();
        assertThat(fetches.get()).isZero();
    }

    @Test
    void memberAnchorsWrittenOutsideHelix_areNotUsed() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()),
                TrustedListFixtures.Pointer.memberState(DE, "DE", deSigner.certificate()));
        serveMember(NL, "NL", 5, 30, nlSigner, Service.granted("NL", nlIssuer));
        serveMember(DE, "DE", 5, 30, deSigner, Service.granted("DE", deIssuer));
        final TrustedListSource created = lotlSource();
        service.refreshNow(realm, created.id());
        final String nlJson = ServicesCodec.encode(List.of(new ListedService(TestPki.create("Injected").root(),
                PID_TYPE, "x", "x", "NL", null)));
        new org.springframework.transaction.support.TransactionTemplate(TRANSACTIONS).executeWithoutResult(t -> {
            JDBC.update("UPDATE trusted_list_member SET services_json = ? WHERE source_id = ? AND territory = 'NL'",
                    nlJson, created.id());
            JDBC.update("UPDATE trusted_list_source SET version = version + 1 WHERE id = ?", created.id());
        });

        final TrustedListService other = newReplica(fetcher);
        other.sync();

        assertThat(anchors(other)).containsExactly(deIssuer);
    }

    @Test
    void withoutDbEncryption_sourcesAreRefusedOutsideDev_andAllowedInDev() {
        final TrustedListService production = new TrustedListService(new TrustedListRepository(JDBC, TRANSACTIONS),
                new TrustedListLoader(fetcher, clock), (r, t, i, o, d) -> { }, clock,
                TrustedListService.Settings.DEFAULTS, TrustedListIntegrity.none(), false);
        assertThatThrownBy(() -> production.create(realm, config("ut")))
                .isInstanceOfSatisfying(TrustedListService.InvalidConfigException.class,
                        e -> assertThat(e.fieldErrors().get("signerCertificates")).contains("DB_ENCRYPTION"));

        final TrustedListService dev = new TrustedListService(new TrustedListRepository(JDBC, TRANSACTIONS),
                new TrustedListLoader(fetcher, clock), (r, t, i, o, d) -> { }, clock,
                TrustedListService.Settings.DEFAULTS, TrustedListIntegrity.none(), true);
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = dev.create(realm, config("ut"));
        dev.refreshNow(realm, created.id());
        assertThat(dev.get(realm, created.id()).orElseThrow().state().servicesMac()).isNull();
        assertThat(dev.anchors(realm, List.of("ut"), List.of())).containsExactly(issuer);
    }

    @Test
    void twoAdmins_theSecondSaveOverAStaleReadIsRefused() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        final long read = cv(created); // both admins read the source now
        final TrustedListSource.Config first = new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(signer.certificate()), List.of(PID_TYPE),
                List.of(), List.of(), 48, true);
        final TrustedListSource.Config second = new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(TrustedListFixtures.signer("Other").certificate()),
                List.of(PID_TYPE), List.of(), List.of(), 24, true);

        service.update(realm, created.id(), first, read);

        assertThatThrownBy(() -> service.update(realm, created.id(), second, read))
                .isInstanceOf(TrustedListService.ConcurrentUpdateException.class);
        final TrustedListSource now = service.get(realm, created.id()).orElseThrow();
        assertThat(now.config().graceHours()).isEqualTo(48);
        assertThat(now.config().signerCertificates()).isEqualTo(TestPki.pem(signer.certificate()));
    }

    @Test
    void everyRefreshTakesTheLeaseWithItsOwnToken() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final List<String> tokens = new CopyOnWriteArrayList<>();
        final String[] id = new String[1];
        final TrustedListService replica = newReplica((url, r) -> {
            tokens.add(JDBC.queryForObject("SELECT lease_owner FROM trusted_list_source WHERE id = ?", String.class,
                    id[0]));
            return fetcher.fetch(url, r);
        });
        id[0] = replica.create(realm, config("ut")).id();

        replica.refreshNow(realm, id[0]);
        replica.refreshNow(realm, id[0]);

        assertThat(tokens).hasSize(2).doesNotContainNull();
        assertThat(tokens.get(0)).isNotEqualTo(tokens.get(1));
    }

    void sql(final String statement, final Object... args) {
        new org.springframework.transaction.support.TransactionTemplate(TRANSACTIONS).executeWithoutResult(t ->
                JDBC.update(statement, args));
    }

    @Test
    void everySettingThatDecidesTrust_isCoveredByTheSettingsMac() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        for (final String tamper : List.of("grace_hours = 700", "enabled = NOT enabled", "name = 'other'",
                "accepted_statuses = '[\"http://example/any\"]'", "territories = '[\"NL\"]'",
                "service_types = '[\"http://example/other\"]'", "url = 'https://evil.example/x.xml'",
                "format = 'ETSI_119602_JSON'")) {
            final String name = "ut" + Math.abs(tamper.hashCode());
            final TrustedListSource created = service.create(realm, config(name));
            service.refreshNow(realm, created.id());
            sql("UPDATE trusted_list_source SET " + tamper + ", version = version + 1 WHERE id = ?", created.id());
            final TrustedListService other = newReplica(fetcher);
            other.sync();
            assertThat(other.anchors(realm, List.of(name, "other"), List.of())).as(tamper).isEmpty();
            assertThat(other.status(other.get(realm, created.id()).orElseThrow())).as(tamper)
                    .isEqualTo(TrustedListHealth.Status.INTEGRITY);
        }
    }

    @Test
    void aSourceMovedToAnotherRealmInTheDatabase_givesNoAnchorsThere() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        sql("UPDATE trusted_list_source SET realm_id = ?, version = version + 1 WHERE id = ?", realm + "-other",
                created.id());
        final TrustedListService other = newReplica(fetcher);
        other.sync();
        assertThat(other.anchors(realm + "-other", List.of("ut"), List.of())).isEmpty();
    }

    @Test
    void storedAnchorsOfAnEarlierConfigVersion_areNotAccepted() {
        serve(listWith(3, Service.granted("Issuer", issuer)));
        final TrustedListSource created = service.create(realm, config("ut"));
        service.refreshNow(realm, created.id());
        final String oldMac = JDBC.queryForObject("SELECT services_mac FROM trusted_list_source WHERE id = ?",
                String.class, created.id());
        final TrustedListSource current = service.get(realm, created.id()).orElseThrow();
        // a settings change that keeps the anchors re-binds them to the new config_version...
        service.update(realm, created.id(), new TrustedListSource.Config("ut", URL,
                TrustedListSpec.Format.ETSI_119612_XML, TestPki.pem(signer.certificate()), List.of(PID_TYPE),
                List.of(), List.of(), 48, true), current.state().configVersion());
        assertThat(anchors(service)).containsExactly(issuer);
        // ...so the earlier row's MAC, put back, no longer verifies
        sql("UPDATE trusted_list_source SET services_mac = ?, version = version + 1 WHERE id = ?", oldMac, created.id());
        final TrustedListService other = newReplica(fetcher);
        other.sync();
        assertThat(anchors(other)).isEmpty();
    }

    @Test
    void graceHoursAreClampedOnRead() {
        final TrustedListRepository repo = new TrustedListRepository(JDBC, TRANSACTIONS);
        final String id = UUID.randomUUID().toString();
        repo.insert(id, realm, new TrustedListSource.Config("huge", URL, TrustedListSpec.Format.ETSI_119612_XML,
                TestPki.pem(signer.certificate()), List.of(PID_TYPE), List.of(), List.of(), 100_000, true),
                clock.millis(), null);
        assertThat(repo.byId(id).orElseThrow().config().graceHours()).isEqualTo(720);
    }

    @Test
    void aTamperedMember_isShownAsAnIntegrityFailure_notInUse() {
        serveLotl(10, TrustedListFixtures.Pointer.memberState(NL, "NL", nlSigner.certificate()));
        serveMember(NL, "NL", 5, 30, nlSigner, Service.granted("NL", nlIssuer));
        final TrustedListSource created = lotlSource();
        service.refreshNow(realm, created.id());
        sql("UPDATE trusted_list_member SET next_update = next_update + 86400000 WHERE source_id = ?", created.id());

        final TrustedListSource source = service.get(realm, created.id()).orElseThrow();
        final TrustedListSource.Member nl = service.members(source).get(0);

        assertThat(service.memberStatus(source, nl)).isEqualTo(TrustedListHealth.Status.INTEGRITY);
        assertThat(service.memberStatus(source, nl).anchorsUsable()).isFalse();
        assertThat(service.services(source)).isEmpty();
    }
}
