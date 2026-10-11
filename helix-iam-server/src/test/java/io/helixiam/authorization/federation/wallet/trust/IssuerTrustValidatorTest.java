/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.KeyType;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.Leaf;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.LeafSpec;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import io.helixiam.common.net.OutboundUrlGuard;
import io.helixiam.testsupport.LogCapture;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IssuerTrustValidatorTest {

    private static TestPki pki;
    /** A localhost port nothing listens on: revocation fetches are refused at once, never hang. */
    private static String closedBase;

    /** The default (secure) guard: CRL/OCSP URLs on private or loopback addresses are never fetched. */
    private final IssuerTrustValidator validator = new IssuerTrustValidator(OutboundUrlGuard.blocking());
    /** Lets the JDK revocation checker actually try the (closed) localhost endpoints. */
    private final IssuerTrustValidator fetching = new IssuerTrustValidator(OutboundUrlGuard.permissive());

    @BeforeAll
    static void setUp() throws Exception {
        // Belt and braces: low JDK revocation timeouts (seconds), in case the classes are not yet loaded.
        System.setProperty("com.sun.security.crl.timeout", "2");
        System.setProperty("com.sun.security.crl.readtimeout", "2");
        System.setProperty("com.sun.security.ocsp.timeout", "2");
        System.setProperty("com.sun.security.ocsp.readtimeout", "2");
        pki = TestPki.create();
        final int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        closedBase = "http://127.0.0.1:" + port;
    }

    private static Leaf leaf(final LeafSpec spec) {
        return pki.issueLeaf(spec);
    }

    private static Leaf revocableLeaf() {
        return leaf(LeafSpec.defaults().withCrlUrl(closedBase + "/issuing.crl").withOcspUrl(closedBase + "/ocsp"));
    }

    private static void assertRejected(final Runnable call, final WalletErrorCode code, final String detail) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(WalletVerificationException.class, e -> {
            assertThat(e.code()).isEqualTo(code);
            assertThat(e.getMessage()).isEqualTo(detail);
        });
    }

    @Test
    void chainToConfiguredAnchorReturnsTheLeaf() {
        final Leaf leaf = leaf(LeafSpec.defaults());

        final X509Certificate result = validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF),
                Instant.now());

        assertThat(result).isEqualTo(leaf.certificate());
    }

    @Test
    void everyAllowedKeyTypeIsAccepted() {
        for (final KeyType type : List.of(KeyType.EC_P256, KeyType.EC_P384, KeyType.EC_P521, KeyType.RSA_2048)) {
            final Leaf leaf = leaf(LeafSpec.defaults().withKeyType(type));
            assertThat(validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), Instant.now()))
                    .as(type.name()).isEqualTo(leaf.certificate());
        }
    }

    @Test
    void chainToAnotherAnchorIsUntrusted() {
        final Leaf leaf = leaf(LeafSpec.defaults());
        final TrustAnchors other = TestPki.create("Other").trustAnchors(RevocationMode.OFF);

        assertRejected(() -> validator.validate(leaf.chain(), other, Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "certificate chain not trusted");
    }

    @Test
    void selfSignedLeafNotInAnchorsIsUntrusted() {
        final Leaf self = TestPki.selfSignedLeaf("CN=Self Signed Issuer");

        assertRejected(() -> validator.validate(self.chain(), pki.trustAnchors(RevocationMode.OFF), Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "leaf certificate is self-signed");
    }

    @Test
    void selfSignedLeafEvenWhenConfiguredAsAnchorIsUntrusted() {
        final Leaf self = TestPki.selfSignedLeaf("CN=Self Signed Issuer");
        final TrustAnchors anchors = TrustAnchors.fromPem(TestPki.pem(self.certificate()), null, RevocationMode.OFF);

        assertRejected(() -> validator.validate(self.chain(), anchors, Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "leaf certificate is self-signed");
    }

    @Test
    void expiredLeafIsUntrustedWithCertificateExpired() {
        final Instant now = Instant.now();
        final Leaf leaf = leaf(LeafSpec.defaults().withValidity(now.minus(Duration.ofDays(30)),
                now.minus(Duration.ofDays(1))));

        assertRejected(() -> validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), now),
                WalletErrorCode.ISSUER_UNTRUSTED, "certificate expired");
    }

    @Test
    void validationUsesTheGivenInstantNotTheClock() {
        final Instant now = Instant.now();
        final Leaf leaf = leaf(LeafSpec.defaults().withValidity(now.minus(Duration.ofDays(30)),
                now.minus(Duration.ofDays(1))));

        assertThat(validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF),
                now.minus(Duration.ofDays(10)))).isEqualTo(leaf.certificate());
    }

    @Test
    void notYetValidLeafIsUntrusted() {
        final Instant now = Instant.now();
        final Leaf leaf = leaf(LeafSpec.defaults().withValidity(now.plus(Duration.ofDays(1)),
                now.plus(Duration.ofDays(30))));

        assertRejected(() -> validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), now),
                WalletErrorCode.ISSUER_UNTRUSTED, "certificate not yet valid");
    }

    @Test
    void leafWithoutDigitalSignatureKeyUsageIsUntrusted() {
        final Leaf leaf = leaf(LeafSpec.defaults().withKeyUsage(KeyUsage.keyEncipherment));

        assertRejected(() -> validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "leaf certificate lacks digitalSignature key usage");
    }

    @Test
    void leafWithoutKeyUsageExtensionIsUntrusted() {
        final Leaf leaf = leaf(LeafSpec.defaults().withKeyUsage(null));

        assertRejected(() -> validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "leaf certificate lacks digitalSignature key usage");
    }

    @Test
    void rootIncludedInChainIsToleratedAndStripped() {
        final Leaf leaf = leaf(LeafSpec.defaults());

        assertThat(validator.validate(pki.withRoot(leaf.chain()), pki.trustAnchors(RevocationMode.OFF),
                Instant.now())).isEqualTo(leaf.certificate());
    }

    @Test
    void missingIntermediateIsFilledFromPinnedIntermediates() {
        final Leaf leaf = leaf(LeafSpec.defaults());
        final TrustAnchors anchors = TrustAnchors.fromPem(pki.rootPem(), pki.intermediatePem(), RevocationMode.OFF);

        assertThat(validator.validate(List.of(leaf.certificate()), anchors, Instant.now()))
                .isEqualTo(leaf.certificate());
    }

    @Test
    void missingIntermediateWithoutPinIsUntrusted() {
        final Leaf leaf = leaf(LeafSpec.defaults());

        assertRejected(() -> validator.validate(List.of(leaf.certificate()), pki.trustAnchors(RevocationMode.OFF),
                Instant.now()), WalletErrorCode.ISSUER_UNTRUSTED, "certificate chain not trusted");
    }

    @Test
    void rsa1024LeafIsAlgorithmNotAllowed() {
        final Leaf leaf = leaf(LeafSpec.defaults().withKeyType(KeyType.RSA_1024));

        assertRejected(() -> validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), Instant.now()),
                WalletErrorCode.ALGORITHM_NOT_ALLOWED, "certificate key type or size not allowed");
    }

    @Test
    void emptyOrNullChainIsUntrusted() {
        final TrustAnchors anchors = pki.trustAnchors(RevocationMode.OFF);
        assertRejected(() -> validator.validate(List.of(), anchors, Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "empty certificate chain");
        assertRejected(() -> validator.validate(null, anchors, Instant.now()),
                WalletErrorCode.ISSUER_UNTRUSTED, "empty certificate chain");
    }

    @Test
    void overlongChainIsALimitError() {
        final Leaf leaf = leaf(LeafSpec.defaults());
        final List<X509Certificate> chain = new ArrayList<>(leaf.chain());
        for (int i = 0; i < 10; i++) {
            chain.add(pki.intermediate());
        }

        assertRejected(() -> validator.validate(chain, pki.trustAnchors(RevocationMode.OFF), Instant.now()),
                WalletErrorCode.LIMIT_EXCEEDED, "certificate chain too long");
    }

    @Test
    void chainOutOfOrderIsUntrusted() {
        final Leaf leaf = leaf(LeafSpec.defaults());

        assertThatThrownBy(() -> validator.validate(List.of(pki.intermediate(), leaf.certificate()),
                pki.trustAnchors(RevocationMode.OFF), Instant.now()))
                .isInstanceOfSatisfying(WalletVerificationException.class,
                        e -> assertThat(e.code()).isEqualTo(WalletErrorCode.ISSUER_UNTRUSTED));
    }

    @Test
    void revocationOffNeverFetches() {
        // The leaf points at closed endpoints; with OFF the chain validates without any revocation attempt.
        final Leaf leaf = revocableLeaf();

        assertThat(fetching.validate(leaf.chain(), pki.trustAnchors(RevocationMode.OFF), Instant.now()))
                .isEqualTo(leaf.certificate());
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void hardFailWithUnreachableRevocationEndpointsIsUntrusted() {
        final Leaf leaf = revocableLeaf();

        assertRejected(() -> fetching.validate(leaf.chain(), pki.trustAnchors(RevocationMode.HARD_FAIL),
                Instant.now()), WalletErrorCode.ISSUER_UNTRUSTED, "certificate revocation status unavailable");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void softFailWithUnreachableRevocationEndpointsPassesAndWarns() {
        final Leaf leaf = revocableLeaf();

        try (LogCapture log = LogCapture.of(IssuerTrustValidator.class)) {
            final X509Certificate result = fetching.validate(leaf.chain(),
                    pki.trustAnchors(RevocationMode.SOFT_FAIL), Instant.now());

            assertThat(result).isEqualTo(leaf.certificate());
            assertThat(log.text()).contains("revocation")
                    .contains(leaf.certificate().getSerialNumber().toString(16))
                    .doesNotContain(closedBase)
                    .doesNotContain("given_name").doesNotContain("family_name");
        }
    }

    @Test
    void hardFailRefusesToFetchFromABlockedAddress() {
        // SSRF: the CRL/OCSP URLs come from the presented certificate; loopback is refused before any fetch.
        final Leaf leaf = revocableLeaf();

        assertRejected(() -> validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.HARD_FAIL),
                Instant.now()), WalletErrorCode.ISSUER_UNTRUSTED, "revocation endpoint not allowed");
    }

    @Test
    void hardFailRefusesNonHttpRevocationEndpoints() {
        final Leaf leaf = leaf(LeafSpec.defaults().withCrlUrl("ldap://ldap.example.com/cn=crl"));

        assertRejected(() -> fetching.validate(leaf.chain(), pki.trustAnchors(RevocationMode.HARD_FAIL),
                Instant.now()), WalletErrorCode.ISSUER_UNTRUSTED, "revocation endpoint not allowed");
    }

    @Test
    void softFailWithABlockedAddressSkipsRevocationAndWarns() {
        final Leaf leaf = revocableLeaf();

        try (LogCapture log = LogCapture.of(IssuerTrustValidator.class)) {
            assertThat(validator.validate(leaf.chain(), pki.trustAnchors(RevocationMode.SOFT_FAIL), Instant.now()))
                    .isEqualTo(leaf.certificate());
            assertThat(log.text()).contains("revocation endpoint not allowed")
                    .contains(leaf.certificate().getSerialNumber().toString(16))
                    .doesNotContain(closedBase);
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void untrustedChainNeverTriggersARevocationFetch() throws Exception {
        try (CountingServer server = new CountingServer()) {
            final Leaf leaf = leaf(LeafSpec.defaults().withCrlUrl(server.base() + "/crl")
                    .withOcspUrl(server.base() + "/ocsp"));
            final TrustAnchors other = TrustAnchors.fromPem(TestPki.create("Other").rootPem(), null,
                    RevocationMode.HARD_FAIL);

            assertRejected(() -> fetching.validate(leaf.chain(), other, Instant.now()),
                    WalletErrorCode.ISSUER_UNTRUSTED, "certificate chain not trusted");
            assertThat(server.connections()).isZero();
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void trustedChainUnderSoftFailDoesContactTheRevocationEndpoint() throws Exception {
        try (CountingServer server = new CountingServer()) {
            final Leaf leaf = leaf(LeafSpec.defaults().withCrlUrl(server.base() + "/crl")
                    .withOcspUrl(server.base() + "/ocsp"));

            assertThat(fetching.validate(leaf.chain(), pki.trustAnchors(RevocationMode.SOFT_FAIL), Instant.now()))
                    .isEqualTo(leaf.certificate());
            assertThat(server.connections()).isPositive();
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void intermediateRevocationIsCheckedToo() throws Exception {
        try (CountingServer server = new CountingServer(); LogCapture log = LogCapture.of(IssuerTrustValidator.class)) {
            final TestPki caPki = TestPki.create("Revocable", server.base() + "/ca");
            final Leaf leaf = caPki.issueLeaf(LeafSpec.defaults());

            assertThat(fetching.validate(leaf.chain(), caPki.trustAnchors(RevocationMode.SOFT_FAIL), Instant.now()))
                    .isEqualTo(leaf.certificate());
            assertThat(server.connections()).isPositive();
            assertThat(log.text()).contains(caPki.intermediate().getSerialNumber().toString(16))
                    .contains(leaf.certificate().getSerialNumber().toString(16));
        }
    }

    @Test
    void hardFailLeafWithoutRevocationPointersIsUntrusted() {
        final Leaf leaf = leaf(LeafSpec.defaults());

        assertRejected(() -> fetching.validate(leaf.chain(), pki.trustAnchors(RevocationMode.HARD_FAIL),
                Instant.now()), WalletErrorCode.ISSUER_UNTRUSTED, "certificate revocation status unavailable");
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void hardFailWithGoodCrlsPasses() throws Exception {
        try (CrlServer server = new CrlServer()) {
            final TestPki caPki = TestPki.create("Good", server.url("/good-root.crl"));
            server.serve("/good-root.crl", caPki.rootCrl());
            server.serve("/good-issuing.crl", caPki.intermediateCrl());
            final Leaf leaf = caPki.issueLeaf(LeafSpec.defaults().withCrlUrl(server.url("/good-issuing.crl")));

            assertThat(fetching.validate(leaf.chain(), caPki.trustAnchors(RevocationMode.HARD_FAIL), Instant.now()))
                    .isEqualTo(leaf.certificate());
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void revokedLeafIsRejectedInBothModes() throws Exception {
        try (CrlServer server = new CrlServer()) {
            final TestPki caPki = TestPki.create("Revoking", server.url("/rev-root.crl"));
            final Leaf leaf = caPki.issueLeaf(LeafSpec.defaults().withCrlUrl(server.url("/rev-issuing.crl")));
            server.serve("/rev-root.crl", caPki.rootCrl());
            server.serve("/rev-issuing.crl", caPki.intermediateCrl(leaf.certificate().getSerialNumber()));

            for (final RevocationMode mode : List.of(RevocationMode.HARD_FAIL, RevocationMode.SOFT_FAIL)) {
                assertRejected(() -> fetching.validate(leaf.chain(), caPki.trustAnchors(mode), Instant.now()),
                        WalletErrorCode.ISSUER_UNTRUSTED, "certificate revoked");
            }
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void revokedIntermediateIsRejected() throws Exception {
        try (CrlServer server = new CrlServer()) {
            final TestPki caPki = TestPki.create("RevokedCa", server.url("/ca-root.crl"));
            server.serve("/ca-root.crl", caPki.rootCrl(caPki.intermediate().getSerialNumber()));
            server.serve("/ca-issuing.crl", caPki.intermediateCrl());
            final Leaf leaf = caPki.issueLeaf(LeafSpec.defaults().withCrlUrl(server.url("/ca-issuing.crl")));

            assertRejected(() -> fetching.validate(leaf.chain(), caPki.trustAnchors(RevocationMode.SOFT_FAIL),
                    Instant.now()), WalletErrorCode.ISSUER_UNTRUSTED, "certificate revoked");
        }
    }

    /** A localhost HTTP server serving DER CRLs. */
    private static final class CrlServer implements AutoCloseable {
        private final HttpServer http;

        CrlServer() throws java.io.IOException {
            http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            http.start();
        }

        String url(final String path) {
            return "http://127.0.0.1:" + http.getAddress().getPort() + path;
        }

        void serve(final String path, final byte[] crl) {
            http.createContext(path, exchange -> {
                exchange.getResponseHeaders().add("Content-Type", "application/pkix-crl");
                exchange.sendResponseHeaders(200, crl.length);
                try (var out = exchange.getResponseBody()) {
                    out.write(crl);
                }
            });
        }

        @Override
        public void close() {
            http.stop(0);
        }
    }

    /** A localhost socket that accepts and immediately closes every connection, counting them. */
    private static final class CountingServer implements AutoCloseable {
        private final ServerSocket socket = new ServerSocket(0);
        private final AtomicInteger count = new AtomicInteger();
        private final Thread acceptor;

        CountingServer() throws java.io.IOException {
            acceptor = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (Socket s = socket.accept()) {
                        count.incrementAndGet();
                    } catch (final java.io.IOException e) {
                        return;
                    }
                }
            }, "counting-revocation-server");
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
