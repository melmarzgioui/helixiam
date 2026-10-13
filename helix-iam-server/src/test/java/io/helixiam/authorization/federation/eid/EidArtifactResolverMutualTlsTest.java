/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import io.helixiam.common.net.OutboundUrlGuard;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The eID back-channel ArtifactResolve, now on the pinned transport, still presents the SP certificate (DigiD's ARS
 * requires mutual TLS): a TLS stub that demands a client certificate sees the SP's, and the request arrives.
 */
class EidArtifactResolverMutualTlsTest {

    private static KeyPair rsa() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate cert(final KeyPair kp, final String dn, final String dnsName) throws Exception {
        final long now = System.currentTimeMillis();
        final org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name(dn);
        final org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder b =
                new org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now),
                        new Date(now - 60_000), new Date(now + 86_400_000L), name, kp.getPublic());
        if (dnsName != null) {
            b.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName, false,
                    new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(
                            org.bouncycastle.asn1.x509.GeneralName.dNSName, dnsName)));
        }
        return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter().getCertificate(
                b.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                        .build(kp.getPrivate())));
    }

    private static String pem(final String type, final byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void theSpCertificateIsPresentedToAnArsThatRequiresClientAuth() throws Exception {
        final KeyPair serverKeys = rsa();
        final X509Certificate serverCert = cert(serverKeys, "CN=ars.mtls.test", "ars.mtls.test");
        final KeyPair spKeys = rsa();
        final X509Certificate spCert = cert(spKeys, "CN=HelixSP", null);

        final KeyStore serverStore = KeyStore.getInstance("PKCS12");
        serverStore.load(null, null);
        serverStore.setKeyEntry("ars", serverKeys.getPrivate(), new char[0], new X509Certificate[] {serverCert});
        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverStore, new char[0]);
        final List<String> presented = new CopyOnWriteArrayList<>();
        final X509TrustManager recordClients = new X509TrustManager() {
            @Override
            public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
                presented.add(chain[0].getSubjectX500Principal().getName());
            }

            @Override
            public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
                throw new UnsupportedOperationException();
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
        final SSLContext serverContext = SSLContext.getInstance("TLS");
        serverContext.init(kmf.getKeyManagers(), new TrustManager[] {recordClients}, null);
        final List<String> requests = new CopyOnWriteArrayList<>();
        try (SSLServerSocket server = (SSLServerSocket) serverContext.getServerSocketFactory().createServerSocket(0, 10,
                InetAddress.getByAddress(new byte[] {127, 0, 0, 1}))) {
            server.setNeedClientAuth(true);
            final Thread t = new Thread(() -> {
                while (!server.isClosed()) {
                    try (SSLSocket s = (SSLSocket) server.accept()) {
                        final InputStream in = s.getInputStream();
                        final byte[] head = in.readNBytes(4); // the handshake completed (or failed) on first read
                        requests.add(new String(head, StandardCharsets.US_ASCII));
                        s.getOutputStream().write("HTTP/1.1 500 X\r\nContent-Length: 0\r\n\r\n"
                                .getBytes(StandardCharsets.US_ASCII));
                    } catch (final Exception e) {
                        // a failed handshake: next
                    }
                }
            }, "ars-mtls");
            t.setDaemon(true);
            t.start();

            final KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ars", serverCert);
            final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            final OutboundUrlGuard guard = new OutboundUrlGuard(false, List.of("ars.mtls.test:" + server.getLocalPort()),
                    host -> new InetAddress[] {InetAddress.getByAddress(host, new byte[] {127, 0, 0, 1})});
            final OpenSamlEidArtifactResolver resolver = new OpenSamlEidArtifactResolver(guard,
                    tmf.getTrustManagers());
            final EidProviderConfig config = new EidProviderConfig(EidScheme.DIGID, "digid", "DigiD",
                    "https://digid.example/sso", "https://digid.example/idp", "https://helix.test/sp",
                    "https://helix.test/acs", null, null, pem("PRIVATE KEY", spKeys.getPrivate().getEncoded()),
                    pem("CERTIFICATE", spCert.getEncoded()), null, null, EidProviderConfig.Binding.POST, null,
                    EidProviderConfig.ResponseBinding.ARTIFACT, "https://ars.mtls.test:" + server.getLocalPort()
                    + "/ars");

            assertThatThrownBy(() -> resolver.resolve(config, "art-1")).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("HTTP 500"); // the stub answers 500 once the request arrived

            assertThat(presented).containsExactly("CN=HelixSP");
            assertThat(requests).containsExactly("POST");
        }
    }
}
