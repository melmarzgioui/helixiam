/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.trust.RevocationTestPki.Ca;
import io.helixiam.common.net.RevocationTimeouts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The JDK's revocation checker is only ever a validator here: whatever it is handed, it never opens a connection of
 * its own (no distribution-point fetch, no OCSP responder contact, no AIA lookup). The certificates below name a
 * local counting server as their CRL distribution point and OCSP responder; every JDK step is given something it
 * cannot accept, which is exactly when the JDK would fall back to fetching.
 */
class JdkRevocationNoFetchTest {

    private static X509CRL parse(final byte[] der) throws Exception {
        return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void aCrlTheJdkCannotApproveNeverMakesItFetchTheDistributionPoint() throws Exception {
        try (Counting server = new Counting()) {
            final Ca root = Ca.root("NoFetch Root");
            final Ca issuing = root.issueCa("NoFetch CA", null, null);
            final X509Certificate leaf = issuing.issueLeaf("NoFetch PID", server.url("/leaf.crl"),
                    server.url("/ocsp"));
            final Instant now = Instant.now();
            // signed by another key: the JDK cannot approve it, and would then try the distribution point itself
            final X509CRL forged = parse(issuing.crlSignedBy(RevocationTestPki.ecKey(), now.plus(Duration.ofDays(1))));

            final IssuerRevocationClient.Answer answer = IssuerRevocationClient.jdkCrl(leaf,
                    new TrustAnchor(issuing.cert, null), forged, now);

            assertThat(answer).isEqualTo(IssuerRevocationClient.Answer.UNDETERMINED);
            assertThat(server.connections()).isZero();
        }
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void anOcspResponseTheJdkCannotAcceptNeverMakesItContactTheResponder() throws Exception {
        try (Counting server = new Counting()) {
            final Ca root = Ca.root("NoFetch Root");
            final Ca issuing = root.issueCa("NoFetch CA", null, null);
            final X509Certificate leaf = issuing.issueLeaf("NoFetch PID", server.url("/leaf.crl"),
                    server.url("/ocsp"));

            final IssuerRevocationClient.Answer answer = IssuerRevocationClient.jdkOcsp(leaf,
                    new TrustAnchor(issuing.cert, null), new byte[] {0x30, 0x03, 0x0a, 0x01, 0x06}, Instant.now());

            assertThat(answer).isEqualTo(IssuerRevocationClient.Answer.UNDETERMINED);
            assertThat(server.connections()).isZero();
        }
    }

    @Test
    void jvmSettingsThatWouldLetTheJdkFetchAreDetected() {
        final String before = System.getProperty("com.sun.security.enableCRLDP");
        try {
            System.setProperty("com.sun.security.enableCRLDP", "false");
            assertThat(IssuerRevocationClient.jdkCannotFetch()).isTrue();
            System.setProperty("com.sun.security.enableCRLDP", "true");
            assertThat(IssuerRevocationClient.jdkCannotFetch()).isFalse();
        } finally {
            if (before == null) {
                System.clearProperty("com.sun.security.enableCRLDP");
            } else {
                System.setProperty("com.sun.security.enableCRLDP", before);
            }
        }
    }

    @Test
    void startupTurnsTheJdksOwnCrlDistributionPointFetchingOff() {
        final Properties props = new Properties();
        props.setProperty("com.sun.security.enableCRLDP", "true");
        RevocationTimeouts.applyDefaults(props);
        assertThat(props.getProperty("com.sun.security.enableCRLDP")).isEqualTo("false");
    }

    /** A localhost socket that accepts and closes every connection, counting them. */
    private static final class Counting implements AutoCloseable {
        private final ServerSocket socket = new ServerSocket(0);
        private final AtomicInteger count = new AtomicInteger();
        private final Thread acceptor;

        Counting() throws java.io.IOException {
            acceptor = new Thread(() -> {
                while (!socket.isClosed()) {
                    try (Socket s = socket.accept()) {
                        count.incrementAndGet();
                    } catch (final java.io.IOException e) {
                        return;
                    }
                }
            }, "jdk-no-fetch");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        String url(final String path) {
            return "http://127.0.0.1:" + socket.getLocalPort() + path;
        }

        int connections() throws InterruptedException {
            Thread.sleep(100);
            return count.get();
        }

        @Override
        public void close() throws Exception {
            socket.close();
            acceptor.join(2_000);
        }
    }
}
