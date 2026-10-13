/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.RevocationTestPki.Answer;
import io.helixiam.authorization.federation.wallet.trust.RevocationTestPki.Ca;
import io.helixiam.authorization.federation.wallet.trust.RevocationTestPki.OcspStatus;
import io.helixiam.authorization.federation.wallet.trust.RevocationTestPki.Stub;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.testsupport.LogCapture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Issuer certificate revocation over HelixIAM's own transport ({@link IssuerRevocationClient}): OCSP and CRL fetched
 * through the outbound guard with a pinned connection, no redirects, size caps, a deadline and a bounded cache, fed to
 * the JDK PKIX revocation checker with its own fetching unused; every certificate of the path evaluated on its own.
 */
class IssuerRevocationTest {

    private static final Instant TOMORROW = Instant.now().plus(Duration.ofDays(1));

    private Stub stub;
    private final MutableClock clock = new MutableClock(Instant.now());

    @BeforeEach
    void start() throws Exception {
        stub = new Stub();
    }

    @AfterEach
    void stop() {
        stub.close();
    }

    private IssuerTrustValidator validator(final OutboundUrlGuard guard, final IssuerRevocationClient.Settings s) {
        return new IssuerTrustValidator(new IssuerRevocationClient(guard, s, clock));
    }

    private IssuerTrustValidator validator() {
        return validator(OutboundUrlGuard.permissive(), IssuerRevocationClient.Settings.DEFAULTS);
    }

    private static void assertRejected(final Runnable call, final String detail) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(WalletVerificationException.class, e -> {
            assertThat(e.code()).isEqualTo(WalletErrorCode.ISSUER_UNTRUSTED);
            assertThat(e.getMessage()).isEqualTo(detail);
        });
    }

    /** root (anchor) → issuing CA (status from the root's CRL) → leaf (status as given). */
    private record TwoLevel(Ca root, Ca issuing, X509Certificate leaf) {
        List<X509Certificate> chain() {
            return List.of(leaf, issuing.cert);
        }
    }

    private TwoLevel twoLevel(final String leafCrl, final String leafOcsp) {
        final Ca root = Ca.root("Rev Root");
        final Ca issuing = root.issueCa("Rev Issuing CA", stub.url("/root.crl"), null);
        stub.serve("/root.crl", root.crl(TOMORROW));
        return new TwoLevel(root, issuing, issuing.issueLeaf("Rev PID Issuer", leafCrl, leafOcsp));
    }

    // ------------------------------------------------------------------------------------------- OCSP

    @Test
    void ocspGoodLeafPassesUnderHardFail() {
        final TwoLevel pki = twoLevel(null, stub.url("/ocsp"));
        stub.ocsp("/ocsp", pki.issuing().ocspResponder(Map.of(), TOMORROW));

        assertThat(validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), Instant.now()))
                .isEqualTo(pki.leaf());
        assertThat(stub.count("/ocsp")).isEqualTo(1);
    }

    @Test
    void ocspRevokedLeafIsRefusedInBothModes() {
        final TwoLevel pki = twoLevel(null, stub.url("/ocsp"));
        stub.ocsp("/ocsp", pki.issuing().ocspResponder(Map.of(pki.leaf().getSerialNumber(), OcspStatus.REVOKED),
                TOMORROW));

        for (final RevocationMode mode : List.of(RevocationMode.HARD_FAIL, RevocationMode.SOFT_FAIL)) {
            assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(mode), Instant.now()),
                    "certificate revoked");
        }
    }

    @Test
    void ocspAnswerSignedByAnotherKeyIsNotAStatus() {
        final TwoLevel pki = twoLevel(null, stub.url("/ocsp"));
        stub.ocsp("/ocsp", pki.issuing().ocspResponder(Map.of(), TOMORROW, RevocationTestPki.ecKey()));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revocation status unavailable");
    }

    @Test
    void ocspUnknownFallsBackToTheCrl() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), stub.url("/ocsp"));
        stub.ocsp("/ocsp", pki.issuing().ocspResponder(Map.of(pki.leaf().getSerialNumber(), OcspStatus.UNKNOWN),
                TOMORROW));
        stub.serve("/issuing.crl", pki.issuing().crl(TOMORROW, pki.leaf().getSerialNumber()));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.SOFT_FAIL),
                Instant.now()), "certificate revoked");
    }

    // ------------------------------------------------------------------------------------------- CRL

    @Test
    void crlRevokedLeafIsRefused() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        stub.serve("/issuing.crl", pki.issuing().crl(TOMORROW, pki.leaf().getSerialNumber()));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revoked");
    }

    @Test
    void crlSignedByAnotherKeyIsNotAcceptedAndOnlyOurFetchHappens() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        stub.serve("/issuing.crl", pki.issuing().crlSignedBy(RevocationTestPki.ecKey(), TOMORROW));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revocation status unavailable");
        // One request: ours. The JDK's own distribution-point fetch (its fallback for a CRL it cannot approve) never
        // runs, because the JDK only ever sees a CRL that already passed our checks.
        assertThat(stub.count("/issuing.crl")).isEqualTo(1);
    }

    @Test
    void staleCrlIsNotAStatus() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        // past nextUpdate by more than the 15-minute clock skew
        stub.serve("/issuing.crl", pki.issuing().crlAt(Instant.now().minus(Duration.ofHours(2)),
                Instant.now().minus(Duration.ofMinutes(16))));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revocation status unavailable");
    }

    // ------------------------------------------------------------------------------------------- clock skew

    /** The JDK's CRL clock skew (RevocationChecker.MAX_CLOCK_SKEW, 900 000 ms). */
    private static final Duration SKEW = Duration.ofMillis(900_000);

    private void assertCrlWindow(final Instant thisUpdate, final Instant nextUpdate, final Instant at,
            final boolean accepted) {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        stub.serve("/issuing.crl", pki.issuing().crlAt(thisUpdate, nextUpdate));
        final Runnable call = () -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), at);
        if (accepted) {
            call.run();
        } else {
            assertRejected(call, "certificate revocation status unavailable");
        }
    }

    @Test
    void aCrlWhoseNextUpdatePassedExactlyFifteenMinutesAgoIsStillUsed() {
        final Instant at = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        assertCrlWindow(at.minus(Duration.ofHours(2)), at.minus(SKEW), at, true);
    }

    @Test
    void aCrlWhoseNextUpdatePassedMoreThanFifteenMinutesAgoIsNot() {
        final Instant at = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        assertCrlWindow(at.minus(Duration.ofHours(2)), at.minus(SKEW).minusSeconds(1), at, false);
    }

    @Test
    void aCrlIssuedExactlyFifteenMinutesInTheFutureIsUsed() {
        final Instant at = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        assertCrlWindow(at.plus(SKEW), at.plus(Duration.ofDays(1)), at, true);
    }

    @Test
    void aCrlIssuedMoreThanFifteenMinutesInTheFutureIsNot() {
        final Instant at = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        assertCrlWindow(at.plus(SKEW).plusSeconds(1), at.plus(Duration.ofDays(1)), at, false);
    }

    @Test
    void aCachedCrlLivesUntilNextUpdatePlusTheSkew() {
        final Instant start = clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        stub.serve("/issuing.crl", pki.issuing().crlAt(start.minus(Duration.ofMinutes(5)),
                start.plus(Duration.ofHours(1))));
        final IssuerTrustValidator v = validator();
        final TrustAnchors anchors = pki.root().anchors(RevocationMode.HARD_FAIL);
        v.validate(pki.chain(), anchors, start);
        clock.advance(Duration.ofHours(1).plus(SKEW).minusSeconds(5));
        v.validate(pki.chain(), anchors, clock.instant());
        assertThat(stub.count("/issuing.crl")).isEqualTo(1);
        clock.advance(Duration.ofSeconds(10));
        stub.serve("/issuing.crl", pki.issuing().crlAt(clock.instant().minus(Duration.ofMinutes(1)),
                clock.instant().plus(Duration.ofHours(1))));
        v.validate(pki.chain(), anchors, clock.instant());
        assertThat(stub.count("/issuing.crl")).isEqualTo(2);
    }

    // ------------------------------------------------------------------------------------------- availability

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void unreachableSoftFailAcceptsAndHardFailRefuses() throws Exception {
        final int closed;
        try (ServerSocket s = new ServerSocket(0)) {
            closed = s.getLocalPort();
        }
        final TwoLevel pki = twoLevel("http://127.0.0.1:" + closed + "/issuing.crl",
                "http://127.0.0.1:" + closed + "/ocsp");

        try (LogCapture log = LogCapture.of(IssuerTrustValidator.class)) {
            assertThat(validator().validate(pki.chain(), pki.root().anchors(RevocationMode.SOFT_FAIL), Instant.now()))
                    .isEqualTo(pki.leaf());
            assertThat(log.text()).contains("revocation status unavailable")
                    .contains(pki.leaf().getSerialNumber().toString(16));
        }
        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revocation status unavailable");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void aRedirectIsNeverFollowed_evenToAPrivateAddress() throws Exception {
        try (CountingSocket target = new CountingSocket()) {
            final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), stub.url("/ocsp"));
            stub.route("/issuing.crl", r -> new Answer(302, new byte[0], 0, target.base() + "/issuing.crl"));
            stub.route("/ocsp", r -> new Answer(307, new byte[0], 0, target.base() + "/ocsp"));

            assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                    Instant.now()), "certificate revocation status unavailable");
            assertThat(target.connections()).isZero();
        }
    }

    @Test
    void anOversizedCrlIsRefused() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        final BigInteger[] many = new BigInteger[400];
        for (int i = 0; i < many.length; i++) {
            many[i] = BigInteger.valueOf(1_000_000L + i);
        }
        final byte[] big = pki.issuing().crl(TOMORROW, many);
        assertThat(big.length).isGreaterThan(4096);
        stub.serve("/issuing.crl", big);
        final IssuerTrustValidator capped = validator(OutboundUrlGuard.permissive(),
                IssuerRevocationClient.Settings.DEFAULTS.withMaxCrlBytes(4096));

        assertRejected(() -> capped.validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), Instant.now()),
                "certificate revocation status unavailable");
        // the same CRL under the default 10 MB cap is fine
        assertThat(validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), Instant.now()))
                .isEqualTo(pki.leaf());
    }

    @Test
    void dnsRebindingCannotMoveTheFetchOffTheValidatedAddress() {
        // The guard allows "crl.test" (allowlisted) at the stub's address on the first answer; every later answer is
        // the cloud-metadata address. The leaf is revoked in the CRL served there, so "certificate revoked" proves the
        // CRL was fetched from the validated address, and one lookup proves nothing resolved the name again.
        final AtomicInteger lookups = new AtomicInteger();
        final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("crl.test:" + stub.port()), host -> {
            final byte[] ip = lookups.getAndIncrement() == 0 ? new byte[] {127, 0, 0, 1}
                    : new byte[] {(byte) 169, (byte) 254, (byte) 169, (byte) 254};
            return new InetAddress[] {InetAddress.getByAddress(host, ip)};
        });
        final Ca root = Ca.root("Rebind Root");
        final Ca issuing = root.issueCa("Rebind Issuing CA", null, null);
        final X509Certificate leaf = issuing.issueLeaf("Rebind PID Issuer",
                "http://crl.test:" + stub.port() + "/issuing.crl", null);
        stub.serve("/issuing.crl", issuing.crl(TOMORROW, leaf.getSerialNumber()));

        assertRejected(() -> validator(guard, IssuerRevocationClient.Settings.DEFAULTS).validate(
                List.of(leaf, issuing.cert), root.anchors(RevocationMode.SOFT_FAIL), Instant.now()),
                "certificate revoked");
        assertThat(lookups).hasValue(1);
        assertThat(stub.hosts).containsExactly("crl.test:" + stub.port());
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void theFetchDeadlineIsHonoured() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        final byte[] crl = pki.issuing().crl(TOMORROW);
        stub.route("/issuing.crl", r -> new Answer(200, crl, 12_000, null));
        final long start = System.nanoTime();

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revocation status unavailable");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(6_500));
    }

    // ------------------------------------------------------------------------------------------- cache

    @Test
    void ocspAndCrlAnswersAreCachedUntilNextUpdate() {
        final Instant nextUpdate = clock.instant().plus(Duration.ofHours(2));
        final Ca root = Ca.root("Cache Root");
        final Ca issuing = root.issueCa("Cache Issuing CA", stub.url("/root.crl"), null);
        stub.serve("/root.crl", root.crl(nextUpdate));
        final X509Certificate leaf = issuing.issueLeaf("Cache PID Issuer", null, stub.url("/ocsp"));
        stub.ocsp("/ocsp", issuing.ocspResponder(Map.of(), nextUpdate));
        final IssuerTrustValidator v = validator();
        final TrustAnchors anchors = root.anchors(RevocationMode.HARD_FAIL);

        v.validate(List.of(leaf, issuing.cert), anchors, clock.instant());
        v.validate(List.of(leaf, issuing.cert), anchors, clock.instant());
        assertThat(stub.count("/ocsp")).isEqualTo(1);
        assertThat(stub.count("/root.crl")).isEqualTo(1);

        clock.advance(Duration.ofHours(2).plus(SKEW).plusSeconds(1)); // past nextUpdate (+ the CRL skew)
        stub.serve("/root.crl", root.crl(clock.instant().plus(Duration.ofHours(2))));
        stub.ocsp("/ocsp", issuing.ocspResponder(Map.of(), clock.instant().plus(Duration.ofHours(2))));
        v.validate(List.of(leaf, issuing.cert), anchors, Instant.now());
        assertThat(stub.count("/ocsp")).isEqualTo(2);
        assertThat(stub.count("/root.crl")).isEqualTo(2);
    }

    @Test
    void anOcspAnswerWithoutNextUpdateIsNotCached() {
        final TwoLevel pki = twoLevel(null, stub.url("/ocsp"));
        stub.ocsp("/ocsp", pki.issuing().ocspResponder(Map.of(), null));
        final IssuerTrustValidator v = validator();

        v.validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), Instant.now());
        v.validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), Instant.now());
        assertThat(stub.count("/ocsp")).isEqualTo(2);
    }

    @Test
    void theCacheIsBoundedByEntriesAndBytes() {
        final IssuerRevocationClient client = new IssuerRevocationClient(OutboundUrlGuard.permissive(),
                IssuerRevocationClient.Settings.DEFAULTS.withCache(2, 1_000_000), clock);
        final IssuerTrustValidator v = new IssuerTrustValidator(client);
        final Ca root = Ca.root("Bound Root");
        final List<TwoLevel> chains = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final Ca issuing = root.issueCa("Bound CA " + i, null, null);
            final X509Certificate leaf = issuing.issueLeaf("Bound PID " + i, stub.url("/c" + i + ".crl"), null);
            stub.serve("/c" + i + ".crl", issuing.crl(TOMORROW));
            chains.add(new TwoLevel(root, issuing, leaf));
        }
        for (final TwoLevel c : chains) {
            v.validate(c.chain(), root.anchors(RevocationMode.SOFT_FAIL), Instant.now());
        }
        assertThat(client.cachedEntries()).isEqualTo(2);
        // the least recently used (c0) was evicted, the two newest are served from the cache
        v.validate(chains.get(2).chain(), root.anchors(RevocationMode.SOFT_FAIL), Instant.now());
        v.validate(chains.get(1).chain(), root.anchors(RevocationMode.SOFT_FAIL), Instant.now());
        assertThat(stub.count("/c1.crl")).isEqualTo(1);
        assertThat(stub.count("/c2.crl")).isEqualTo(1);
        v.validate(chains.get(0).chain(), root.anchors(RevocationMode.SOFT_FAIL), Instant.now());
        assertThat(stub.count("/c0.crl")).isEqualTo(2);

        final int oneCrl = 3 * chains.get(0).issuing().crl(TOMORROW).length; // the parsed-heap estimate, no entries
        final IssuerRevocationClient small = new IssuerRevocationClient(OutboundUrlGuard.permissive(),
                IssuerRevocationClient.Settings.DEFAULTS.withCache(100, oneCrl * 2L + oneCrl / 2), clock);
        final IssuerTrustValidator sv = new IssuerTrustValidator(small);
        for (final TwoLevel c : chains) {
            sv.validate(c.chain(), root.anchors(RevocationMode.SOFT_FAIL), Instant.now());
        }
        assertThat(small.cachedEntries()).isEqualTo(2);
        assertThat(small.cachedBytes()).isLessThanOrEqualTo(oneCrl * 2L + oneCrl / 2);
    }

    // ------------------------------------------------------------------------------------------- concurrency

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void concurrentLoginsShareOneCrlFetch() throws Exception {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        final byte[] crl = pki.issuing().crl(TOMORROW);
        stub.route("/issuing.crl", r -> new Answer(200, crl, 400, null));
        final IssuerTrustValidator v = validator();
        final java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(8);
        try {
            final List<java.util.concurrent.Future<X509Certificate>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> {
                    go.await();
                    return v.validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL), Instant.now());
                }));
            }
            go.countDown();
            for (final var r : results) {
                assertThat(r.get(20, TimeUnit.SECONDS)).isEqualTo(pki.leaf());
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(stub.count("/issuing.crl")).isEqualTo(1);
        assertThat(stub.count("/root.crl")).isEqualTo(1);
    }

    @Test
    void aCrlThatDoesNotParseIsNotDownloadedAgainForAMinute() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        stub.serve("/issuing.crl", "<html>not a CRL</html>".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        final IssuerTrustValidator v = validator();
        final TrustAnchors anchors = pki.root().anchors(RevocationMode.SOFT_FAIL);
        v.validate(pki.chain(), anchors, Instant.now());
        clock.advance(Duration.ofSeconds(59));
        v.validate(pki.chain(), anchors, Instant.now());
        assertThat(stub.count("/issuing.crl")).isEqualTo(1);
        clock.advance(Duration.ofSeconds(2));
        v.validate(pki.chain(), anchors, Instant.now());
        assertThat(stub.count("/issuing.crl")).isEqualTo(2);
    }

    @Test
    void anOversizedCrlIsNotDownloadedAgainForAMinute() {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        stub.serve("/issuing.crl", new byte[8192]);
        final IssuerTrustValidator capped = validator(OutboundUrlGuard.permissive(),
                IssuerRevocationClient.Settings.DEFAULTS.withMaxCrlBytes(4096));
        final TrustAnchors anchors = pki.root().anchors(RevocationMode.SOFT_FAIL);
        capped.validate(pki.chain(), anchors, Instant.now());
        capped.validate(pki.chain(), anchors, Instant.now());
        assertThat(stub.count("/issuing.crl")).isEqualTo(1);
    }

    @Test
    void aCachedCrlCountsItsParsedSizeNotItsEncodedSize() throws Exception {
        final TwoLevel pki = twoLevel(stub.url("/issuing.crl"), null);
        final BigInteger[] many = new BigInteger[400];
        for (int i = 0; i < many.length; i++) {
            many[i] = BigInteger.valueOf(2_000_000L + i);
        }
        final byte[] encoded = pki.issuing().crl(TOMORROW, many);
        stub.serve("/issuing.crl", encoded);
        final java.security.cert.X509CRL parsed = (java.security.cert.X509CRL) java.security.cert.CertificateFactory
                .getInstance("X.509").generateCRL(new java.io.ByteArrayInputStream(encoded));
        final long estimate = IssuerRevocationClient.crlHeapEstimate(parsed, encoded.length);
        assertThat(estimate).isEqualTo(3L * encoded.length + 400L * IssuerRevocationClient.CRL_ENTRY_OVERHEAD);

        // a budget that fits the encoded CRL (twice over) but not its parsed estimate: not cached
        final IssuerRevocationClient client = new IssuerRevocationClient(OutboundUrlGuard.permissive(),
                IssuerRevocationClient.Settings.DEFAULTS.withCache(100, 2L * encoded.length), clock);
        new IssuerTrustValidator(client).validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now());
        assertThat(client.cachedBytes()).isLessThan(estimate);
        final IssuerRevocationClient roomy = new IssuerRevocationClient(OutboundUrlGuard.permissive(),
                IssuerRevocationClient.Settings.DEFAULTS, clock);
        new IssuerTrustValidator(roomy).validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now());
        assertThat(roomy.cachedBytes()).isGreaterThanOrEqualTo(estimate);
    }

    // ------------------------------------------------------------------------------------------- path

    /** root (anchor) → upper CA (status: root's CRL, unreachable) → lower CA → leaf. */
    private record ThreeLevel(Ca root, Ca upper, Ca lower, X509Certificate leaf) {
        List<X509Certificate> chain() {
            return List.of(leaf, lower.cert, upper.cert);
        }
    }

    private ThreeLevel threeLevel() throws Exception {
        final int closed;
        try (ServerSocket s = new ServerSocket(0)) {
            closed = s.getLocalPort();
        }
        final Ca root = Ca.root("Deep Root");
        final Ca upper = root.issueCa("Deep Upper CA", "http://127.0.0.1:" + closed + "/root.crl", null);
        final Ca lower = upper.issueCa("Deep Lower CA", stub.url("/upper.crl"), null);
        final X509Certificate leaf = lower.issueLeaf("Deep PID Issuer", stub.url("/lower.crl"), null);
        return new ThreeLevel(root, upper, lower, leaf);
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void twoIntermediates_upperUnavailable_revokedLeafIsRefused() throws Exception {
        final ThreeLevel pki = threeLevel();
        stub.serve("/upper.crl", pki.upper().crl(TOMORROW));
        stub.serve("/lower.crl", pki.lower().crl(TOMORROW, pki.leaf().getSerialNumber()));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.SOFT_FAIL),
                Instant.now()), "certificate revoked");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void twoIntermediates_upperUnavailable_revokedLowerCaIsRefused() throws Exception {
        final ThreeLevel pki = threeLevel();
        stub.serve("/upper.crl", pki.upper().crl(TOMORROW, pki.lower().cert.getSerialNumber()));
        stub.serve("/lower.crl", pki.lower().crl(TOMORROW));

        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.SOFT_FAIL),
                Instant.now()), "certificate revoked");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void twoIntermediates_softFailWarnsOnlyForTheUndeterminedCertificate() throws Exception {
        final ThreeLevel pki = threeLevel();
        stub.serve("/upper.crl", pki.upper().crl(TOMORROW));
        stub.serve("/lower.crl", pki.lower().crl(TOMORROW));

        try (LogCapture log = LogCapture.of(IssuerTrustValidator.class)) {
            assertThat(validator().validate(pki.chain(), pki.root().anchors(RevocationMode.SOFT_FAIL), Instant.now()))
                    .isEqualTo(pki.leaf());
            assertThat(log.text()).contains(pki.upper().cert.getSerialNumber().toString(16))
                    .doesNotContain(pki.lower().cert.getSerialNumber().toString(16))
                    .doesNotContain(pki.leaf().getSerialNumber().toString(16));
        }
        assertRejected(() -> validator().validate(pki.chain(), pki.root().anchors(RevocationMode.HARD_FAIL),
                Instant.now()), "certificate revocation status unavailable");
    }

    // ------------------------------------------------------------------------------------------- defaults

    @Test
    void maxCrlBytesIsCappedAt100Megabytes() {
        assertThat(IssuerRevocationClient.Settings.MAX_CRL_BYTES_CAP).isEqualTo(100L * 1024 * 1024);
        assertThat(IssuerRevocationClient.Settings.DEFAULTS.withMaxCrlBytes(100L * 1024 * 1024).maxCrlBytes())
                .isEqualTo(100L * 1024 * 1024);
        assertThatThrownBy(() -> IssuerRevocationClient.Settings.DEFAULTS.withMaxCrlBytes(100L * 1024 * 1024 + 1))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("max-crl-bytes");
        assertThatThrownBy(() -> IssuerRevocationClient.Settings.DEFAULTS.withMaxCrlBytes(0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void hardFailIsTheDefaultMode() {
        assertThat(new TrustAnchors(null, null, null).revocation()).isEqualTo(RevocationMode.HARD_FAIL);
    }

    // ------------------------------------------------------------------------------------------- helpers

    /** A settable clock (cache-expiry tests). */
    static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(final Instant now) {
            this.now = now;
        }

        void advance(final Duration d) {
            now = now.plus(d);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(final java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** A localhost socket that accepts and closes every connection, counting them. */
    private static final class CountingSocket implements AutoCloseable {
        private final ServerSocket socket = new ServerSocket(0);
        private final AtomicInteger count = new AtomicInteger();
        private final Thread acceptor;

        CountingSocket() throws java.io.IOException {
            acceptor = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (Socket s = socket.accept()) {
                        count.incrementAndGet();
                    } catch (final java.io.IOException e) {
                        return;
                    }
                }
            }, "counting-redirect-target");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        String base() {
            return "http://127.0.0.1:" + socket.getLocalPort();
        }

        int connections() {
            return count.get();
        }

        @Override
        public void close() throws Exception {
            socket.close();
            acceptor.join(2_000);
        }
    }
}
