/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A throwaway test CA and a server certificate it signed for {@code localhost} and {@code 127.0.0.1}: the server side
 * ({@link #serverContext()}) for a local TLS test server, and the CA as PEM ({@link #caPem()}) for a client's CA
 * bundle. A client that does not trust the CA fails certificate validation.
 */
public final class TestTls {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private final X509Certificate ca;
    private final SSLContext serverContext;

    private TestTls(final X509Certificate ca, final SSLContext serverContext) {
        this.ca = ca;
        this.serverContext = serverContext;
    }

    /** A new CA and a server certificate for localhost / 127.0.0.1. */
    public static TestTls create(final String name) {
        return create(name, new GeneralName[] {new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")});
    }

    /** A new CA and a server certificate for {@code dnsName} only (a host-name mismatch on localhost). */
    public static TestTls createFor(final String name, final String dnsName) {
        return create(name, new GeneralName[] {new GeneralName(GeneralName.dNSName, dnsName)});
    }

    private static TestTls create(final String name, final GeneralName[] names) {
        try {
            final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            final KeyPair caKeys = gen.generateKeyPair();
            final X500Name caName = new X500Name("CN=" + name + " Test CA");
            final Date from = new Date(System.currentTimeMillis() - 3_600_000L);
            final Date to = new Date(System.currentTimeMillis() + 86_400_000L);
            final X509Certificate ca = sign(new JcaX509v3CertificateBuilder(caName, serial(), from, to, caName,
                    caKeys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)),
                    caKeys);

            final KeyPair serverKeys = gen.generateKeyPair();
            final X509Certificate server = sign(new JcaX509v3CertificateBuilder(caName, serial(), from, to,
                    new X500Name("CN=" + names[0].getName()), serverKeys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names)), caKeys);

            final KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("server", serverKeys.getPrivate(), "changeit".toCharArray(), new Certificate[] {server, ca});
            final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, "changeit".toCharArray());
            final SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            return new TestTls(ca, ctx);
        } catch (final Exception e) {
            throw new IllegalStateException("Could not create the test TLS material", e);
        }
    }

    private static X509Certificate sign(final org.bouncycastle.cert.X509v3CertificateBuilder builder, final KeyPair signer)
            throws Exception {
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())));
    }

    private static BigInteger serial() {
        return BigInteger.valueOf(SERIAL.incrementAndGet());
    }

    /** The server's TLS context (its certificate chain up to the test CA). */
    public SSLContext serverContext() {
        return serverContext;
    }

    /** The test CA certificate as PEM (a client's {@code caBundle}). */
    public String caPem() {
        try {
            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(ca.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
