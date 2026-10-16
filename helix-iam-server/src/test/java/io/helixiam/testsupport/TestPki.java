/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.testsupport;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/** A throw-away PKI for tests: key pairs, a CA, issued and self-signed certificates, PEM, CSR signing. */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private TestPki() {
    }

    public static KeyPair rsa(final int bits) {
        try {
            final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(bits);
            return g.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair ec(final String curve) {
        try {
            final KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec(curve));
            return g.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** An EC key pair on any curve BouncyCastle knows (e.g. secp256k1, which the JDK no longer has). */
    public static KeyPair ecBc(final String curve) {
        try {
            final KeyPairGenerator g = KeyPairGenerator.getInstance("EC",
                    new org.bouncycastle.jce.provider.BouncyCastleProvider());
            g.initialize(new ECGenParameterSpec(curve));
            return g.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A CA: key pair + self-signed CA certificate. */
    public record Ca(KeyPair keyPair, X509Certificate certificate) {
    }

    public static Ca ca(final String cn) {
        final KeyPair kp = rsa(2048);
        final X509Certificate cert = build(new X500Name("CN=" + cn), kp.getPublic(), new X500Name("CN=" + cn),
                kp.getPrivate(), Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(3650)),
                true, KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return new Ca(kp, cert);
    }

    /** A certificate for {@code subjectKey} issued by {@code ca}, valid from yesterday for {@code days}. */
    public static X509Certificate issue(final Ca ca, final String subjectDn, final PublicKey subjectKey, final int days) {
        return issue(ca.certificate(), ca.keyPair().getPrivate(), subjectDn, subjectKey,
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(days)),
                KeyUsage.digitalSignature);
    }

    /** A leaf that (wrongly) says CA:true. */
    public static X509Certificate issueCaLeaf(final Ca ca, final String subjectDn, final PublicKey subjectKey) {
        return build(new X500Name(subjectDn), subjectKey,
                new X500Name(ca.certificate().getSubjectX500Principal().getName()), ca.keyPair().getPrivate(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(30)), true,
                KeyUsage.digitalSignature | KeyUsage.keyCertSign);
    }

    /** An "issuer" certificate that is not a CA (no basicConstraints CA:true), with the given key usage. */
    public static Ca nonCaIssuer(final Ca root, final String cn, final int keyUsage) {
        final KeyPair kp = rsa(2048);
        final X509Certificate cert = build(new X500Name("CN=" + cn), kp.getPublic(),
                new X500Name(root.certificate().getSubjectX500Principal().getName()), root.keyPair().getPrivate(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(100)), false, keyUsage);
        return new Ca(kp, cert);
    }

    /** An RSA key pair with an explicit public exponent. */
    public static KeyPair rsa(final int bits, final java.math.BigInteger exponent) {
        try {
            final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(new java.security.spec.RSAKeyGenParameterSpec(bits, exponent));
            return g.generateKeyPair();
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A CA with keyCertSign missing from its keyUsage. */
    public static Ca caWithoutKeyCertSign(final String cn) {
        final KeyPair kp = rsa(2048);
        final X509Certificate cert = build(new X500Name("CN=" + cn), kp.getPublic(), new X500Name("CN=" + cn),
                kp.getPrivate(), Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(100)),
                true, KeyUsage.digitalSignature);
        return new Ca(kp, cert);
    }

    /** A certificate with an explicit window and key usage ({@code keyUsage < 0}: no keyUsage extension). */
    public static X509Certificate issue(final X509Certificate issuer, final PrivateKey issuerKey, final String subjectDn,
                                        final PublicKey subjectKey, final Instant notBefore, final Instant notAfter,
                                        final int keyUsage) {
        return build(new X500Name(subjectDn), subjectKey,
                new X500Name(issuer.getSubjectX500Principal().getName()), issuerKey, notBefore, notAfter, false,
                keyUsage);
    }

    public static X509Certificate selfSigned(final KeyPair kp, final String dn, final int days) {
        return build(new X500Name(dn), kp.getPublic(), new X500Name(dn), kp.getPrivate(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(days)), false,
                KeyUsage.digitalSignature);
    }

    /** An intermediate CA issued by {@code root}. */
    public static Ca intermediate(final Ca root, final String cn) {
        final KeyPair kp = rsa(2048);
        final X509Certificate cert = build(new X500Name("CN=" + cn), kp.getPublic(),
                new X500Name(root.certificate().getSubjectX500Principal().getName()), root.keyPair().getPrivate(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(1000)), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign);
        return new Ca(kp, cert);
    }

    /** Signs a PEM PKCS#10 request with {@code ca}, as a CA would (subject and key from the CSR). */
    public static X509Certificate signCsr(final Ca ca, final String csrPem, final int days) {
        try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
            final PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parser.readObject();
            final JcaPKCS10CertificationRequest jca = new JcaPKCS10CertificationRequest(csr);
            return issue(ca, csr.getSubject().toString(), jca.getPublicKey(), days);
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pem(final Object... objects) {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            for (final Object o : objects) {
                w.writeObject(o);
            }
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
        return out.toString();
    }

    /** PKCS#8 PEM ({@code BEGIN PRIVATE KEY}). */
    public static String pkcs8(final PrivateKey key) {
        try {
            return pem(new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(key, null).generate());
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** PKCS#1 / SEC1 PEM ({@code BEGIN RSA PRIVATE KEY} / {@code BEGIN EC PRIVATE KEY}). */
    public static String traditional(final KeyPair kp) {
        if (kp.getPrivate() instanceof java.security.interfaces.ECPrivateKey ec) {
            // SEC1 as openssl writes it: with the named curve and the public key (the JDK's own encoding omits both).
            try {
                final org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
                        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
                final org.bouncycastle.asn1.sec.ECPrivateKey sec1 = new org.bouncycastle.asn1.sec.ECPrivateKey(
                        ec.getParams().getOrder().bitLength(), ec.getS(), spki.getPublicKeyData(),
                        spki.getAlgorithm().getParameters());
                return pem(new org.bouncycastle.util.io.pem.PemObject("EC PRIVATE KEY", sec1.getEncoded()));
            } catch (final Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return pem(kp);
    }

    private static X509Certificate build(final X500Name subject, final PublicKey subjectKey, final X500Name issuer,
                                         final PrivateKey issuerKey, final Instant notBefore, final Instant notAfter,
                                         final boolean ca, final int keyUsage) {
        try {
            final X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer,
                    BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(notBefore), Date.from(notAfter), subject,
                    subjectKey);
            if (ca) {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            }
            if (keyUsage >= 0) {
                b.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            }
            final String sigAlg = "RSA".equals(issuerKey.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
            return new JcaX509CertificateConverter().getCertificate(
                    b.build(new JcaContentSignerBuilder(sigAlg).build(issuerKey)));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
