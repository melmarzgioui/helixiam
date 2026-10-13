/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.testwallet;

import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A throwaway issuer PKI for wallet tests: a self-signed root CA, an intermediate CA it signed, and leaf (issuer
 * signing) certificates issued by the intermediate with a chosen key type, key usage, validity and revocation
 * pointers.
 *
 * <pre>{@code
 * TestPki pki = TestPki.create();
 * TestPki.Leaf leaf = pki.issueLeaf(TestPki.LeafSpec.defaults());          // EC P-256, digitalSignature
 * leaf.chain();                                                          // [leaf, intermediate] as in x5c
 * pki.trustAnchors(TrustAnchors.RevocationMode.OFF);                     // the root as the only anchor
 * }</pre>
 */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    /** Key types a test certificate can carry. */
    public enum KeyType {
        EC_P256, EC_P384, EC_P521, RSA_1024, RSA_2048;

        KeyPair generate() {
            try {
                return switch (this) {
                    case EC_P256 -> ec("secp256r1");
                    case EC_P384 -> ec("secp384r1");
                    case EC_P521 -> ec("secp521r1");
                    case RSA_1024 -> rsa(1024);
                    case RSA_2048 -> rsa(2048);
                };
            } catch (final Exception e) {
                throw new IllegalStateException("Could not generate a " + this + " key", e);
            }
        }

        String signatureAlgorithm() {
            return switch (this) {
                case EC_P256 -> "SHA256withECDSA";
                case EC_P384 -> "SHA384withECDSA";
                case EC_P521 -> "SHA512withECDSA";
                case RSA_1024, RSA_2048 -> "SHA256withRSA";
            };
        }

        private static KeyPair ec(final String curve) throws Exception {
            final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec(curve));
            return gen.generateKeyPair();
        }

        private static KeyPair rsa(final int bits) throws Exception {
            final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(bits);
            return gen.generateKeyPair();
        }
    }

    /**
     * What a leaf looks like. {@code keyUsage} is a BouncyCastle {@link KeyUsage} bit mask, or {@code null} for no
     * key-usage extension. {@code crlUrl} / {@code ocspUrl} are {@code null} for none.
     */
    public record LeafSpec(String subject, KeyType keyType, Integer keyUsage, Instant notBefore, Instant notAfter,
            String crlUrl, String ocspUrl, List<String> dnsNames) {

        public LeafSpec {
            dnsNames = dnsNames == null ? List.of() : List.copyOf(dnsNames);
        }

        /** EC P-256, {@code digitalSignature}, valid from one day ago for a year, no revocation pointers. */
        public static LeafSpec defaults() {
            final Instant now = Instant.now();
            return new LeafSpec("CN=Test PID Issuer,O=HelixIAM Test", KeyType.EC_P256, KeyUsage.digitalSignature,
                    now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(365)), null, null, List.of());
        }

        public LeafSpec withSubject(final String value) {
            return new LeafSpec(value, keyType, keyUsage, notBefore, notAfter, crlUrl, ocspUrl, dnsNames);
        }

        public LeafSpec withKeyType(final KeyType value) {
            return new LeafSpec(subject, value, keyUsage, notBefore, notAfter, crlUrl, ocspUrl, dnsNames);
        }

        public LeafSpec withKeyUsage(final Integer value) {
            return new LeafSpec(subject, keyType, value, notBefore, notAfter, crlUrl, ocspUrl, dnsNames);
        }

        public LeafSpec withValidity(final Instant from, final Instant to) {
            return new LeafSpec(subject, keyType, keyUsage, from, to, crlUrl, ocspUrl, dnsNames);
        }

        public LeafSpec withCrlUrl(final String value) {
            return new LeafSpec(subject, keyType, keyUsage, notBefore, notAfter, value, ocspUrl, dnsNames);
        }

        public LeafSpec withOcspUrl(final String value) {
            return new LeafSpec(subject, keyType, keyUsage, notBefore, notAfter, crlUrl, value, dnsNames);
        }

        /** dNSName subjectAltName entries (e.g. a verifier access certificate for {@code x509_san_dns}). */
        public LeafSpec withDnsNames(final String... value) {
            return new LeafSpec(subject, keyType, keyUsage, notBefore, notAfter, crlUrl, ocspUrl, List.of(value));
        }
    }

    /** An issued leaf: its certificate, its private key and the x5c-style chain {@code [leaf, intermediate]}. */
    public record Leaf(X509Certificate certificate, PrivateKey privateKey, List<X509Certificate> chain) {
    }

    private final KeyPair rootKeys;
    private final X509Certificate root;
    private final KeyPair intermediateKeys;
    private final X509Certificate intermediate;

    private TestPki(final KeyPair rootKeys, final X509Certificate root, final KeyPair intermediateKeys,
            final X509Certificate intermediate) {
        this.rootKeys = rootKeys;
        this.root = root;
        this.intermediateKeys = intermediateKeys;
        this.intermediate = intermediate;
    }

    /** A new EC P-256 root and intermediate CA, valid from one year ago for ten years. */
    public static TestPki create() {
        return create("HelixIAM Test");
    }

    /** As {@link #create()}, with {@code name} in the CA subjects (two PKIs with distinct names). */
    public static TestPki create(final String name) {
        return create(name, null);
    }

    /**
     * As {@link #create(String)}; when {@code intermediateRevocationUrl} is not null the intermediate carries it as
     * both its CRL distribution point and its OCSP responder.
     */
    public static TestPki create(final String name, final String intermediateRevocationUrl) {
        final Instant now = Instant.now();
        final Instant from = now.minus(Duration.ofDays(365));
        final Instant to = now.plus(Duration.ofDays(3650));
        final KeyPair rootKeys = KeyType.EC_P256.generate();
        final X500Name rootName = new X500Name("CN=" + name + " Root CA");
        final X509Certificate root = sign(ca(rootName, rootName, rootKeys, rootKeys, from, to, 1),
                rootKeys.getPrivate(), KeyType.EC_P256);
        final KeyPair intermediateKeys = KeyType.EC_P256.generate();
        final X509v3CertificateBuilder intermediateBuilder = ca(rootName, new X500Name("CN=" + name + " Issuing CA"),
                intermediateKeys, rootKeys, from, to, 0);
        if (intermediateRevocationUrl != null) {
            addRevocationPointers(intermediateBuilder, intermediateRevocationUrl, intermediateRevocationUrl);
        }
        final X509Certificate intermediate = sign(intermediateBuilder, rootKeys.getPrivate(), KeyType.EC_P256);
        return new TestPki(rootKeys, root, intermediateKeys, intermediate);
    }

    /**
     * A second issuing CA ("CN={@code name} Issuing CA") under this PKI's root: a sibling issuer sharing the root, with
     * its own key. Its {@link #root()} is this root.
     */
    public TestPki siblingIssuer(final String name) {
        final Instant now = Instant.now();
        final KeyPair keys = KeyType.EC_P256.generate();
        final X509Certificate sibling = sign(ca(X500Name.getInstance(root.getSubjectX500Principal().getEncoded()),
                new X500Name("CN=" + name + " Issuing CA"), keys, rootKeys, now.minus(Duration.ofDays(365)),
                now.plus(Duration.ofDays(3650)), 0), rootKeys.getPrivate(), KeyType.EC_P256);
        return new TestPki(rootKeys, root, keys, sibling);
    }

    /** A leaf issued by the intermediate. */
    public Leaf issueLeaf(final LeafSpec spec) {
        final KeyPair keys = spec.keyType().generate();
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(intermediate.getSubjectX500Principal().getEncoded()), serial(),
                Date.from(spec.notBefore()), Date.from(spec.notAfter()), new X500Name(spec.subject()),
                keys.getPublic());
        try {
            final JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.subjectKeyIdentifier, false,
                            ext.createSubjectKeyIdentifier(keys.getPublic()))
                    .addExtension(Extension.authorityKeyIdentifier, false,
                            ext.createAuthorityKeyIdentifier(intermediateKeys.getPublic()));
            if (spec.keyUsage() != null) {
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(spec.keyUsage()));
            }
            if (!spec.dnsNames().isEmpty()) {
                builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(spec.dnsNames().stream()
                        .map(n -> new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new)));
            }
            addRevocationPointers(builder, spec.crlUrl(), spec.ocspUrl());
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build the leaf certificate", e);
        }
        // The intermediate (EC P-256) signs every leaf, whatever the leaf's own key type.
        final X509Certificate cert = sign(builder, intermediateKeys.getPrivate(), KeyType.EC_P256);
        return new Leaf(cert, keys.getPrivate(), List.of(cert, intermediate));
    }

    /** A self-signed end-entity certificate (EC P-256, digitalSignature) that chains to nothing. */
    public static Leaf selfSignedLeaf(final String subject) {
        final KeyPair keys = KeyType.EC_P256.generate();
        final Instant now = Instant.now();
        final X500Name name = new X500Name(subject);
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(),
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))), name,
                keys.getPublic());
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
        final X509Certificate cert = sign(builder, keys.getPrivate(), KeyType.EC_P256);
        return new Leaf(cert, keys.getPrivate(), List.of(cert));
    }

    /** A DER CRL issued by the intermediate (covers leaves), revoking {@code serials}; valid for a day. */
    public byte[] intermediateCrl(final BigInteger... serials) {
        return crl(intermediate, intermediateKeys.getPrivate(), serials);
    }

    /** A DER CRL issued by the root (covers the intermediate), revoking {@code serials}; valid for a day. */
    public byte[] rootCrl(final BigInteger... serials) {
        return crl(root, rootKeys.getPrivate(), serials);
    }

    private static byte[] crl(final X509Certificate issuer, final PrivateKey key, final BigInteger... serials) {
        final Instant now = Instant.now();
        final X509v2CRLBuilder builder = new X509v2CRLBuilder(
                X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                Date.from(now.minus(Duration.ofMinutes(5))));
        builder.setNextUpdate(Date.from(now.plus(Duration.ofDays(1))));
        for (final BigInteger serial : serials) {
            builder.addCRLEntry(serial, Date.from(now.minus(Duration.ofMinutes(1))), CRLReason.keyCompromise);
        }
        try {
            return builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key)).getEncoded();
        } catch (final Exception e) {
            throw new IllegalStateException("Could not sign the test CRL", e);
        }
    }

    /**
     * A self-signed CA certificate (basicConstraints cA=true) with the given key type and key usage ({@code null}: no
     * key-usage extension), for anchor-loading tests.
     */
    public static X509Certificate caCertificate(final KeyType keyType, final Integer keyUsage) {
        final KeyPair keys = keyType.generate();
        final Instant now = Instant.now();
        final X500Name name = new X500Name("CN=Test " + keyType + " CA");
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, serial(),
                Date.from(now.minus(Duration.ofDays(1))), Date.from(now.plus(Duration.ofDays(365))), name,
                keys.getPublic());
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            if (keyUsage != null) {
                builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            }
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
        return sign(builder, keys.getPrivate(), keyType);
    }

    public X509Certificate root() {
        return root;
    }

    public X509Certificate intermediate() {
        return intermediate;
    }

    /** The root alone as an anchor, no pinned intermediates. */
    public TrustAnchors trustAnchors(final TrustAnchors.RevocationMode mode) {
        return TrustAnchors.fromPem(rootPem(), null, mode);
    }

    public String rootPem() {
        return pem(root);
    }

    public String intermediatePem() {
        return pem(intermediate);
    }

    /** One certificate as a PEM block. */
    public static String pem(final X509Certificate cert) {
        try {
            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code chain} followed by the root (an x5c that wrongly includes the trust anchor). */
    public List<X509Certificate> withRoot(final List<X509Certificate> chain) {
        final List<X509Certificate> out = new ArrayList<>(chain);
        out.add(root);
        return List.copyOf(out);
    }

    private static void addRevocationPointers(final X509v3CertificateBuilder builder, final String crlUrl,
            final String ocspUrl) {
        try {
            if (crlUrl != null) {
                final GeneralNames names = new GeneralNames(
                        new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl));
                builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[] {
                        new DistributionPoint(new DistributionPointName(names), null, null)}));
            }
            if (ocspUrl != null) {
                builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                        AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
            }
        } catch (final Exception e) {
            throw new IllegalStateException("Could not add the revocation pointers", e);
        }
    }

    private static X509v3CertificateBuilder ca(final X500Name issuer, final X500Name subject, final KeyPair subjectKeys,
            final KeyPair issuerKeys, final Instant from, final Instant to, final int pathLen) {
        try {
            final JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            return new JcaX509v3CertificateBuilder(issuer, serial(), Date.from(from), Date.from(to), subject,
                    subjectKeys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
                    .addExtension(Extension.subjectKeyIdentifier, false,
                            ext.createSubjectKeyIdentifier(subjectKeys.getPublic()))
                    .addExtension(Extension.authorityKeyIdentifier, false,
                            ext.createAuthorityKeyIdentifier(issuerKeys.getPublic()));
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build the CA certificate", e);
        }
    }

    private static X509Certificate sign(final X509v3CertificateBuilder builder, final PrivateKey signer,
            final KeyType signerType) {
        try {
            return new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder(signerType.signatureAlgorithm()).build(signer)));
        } catch (final Exception e) {
            throw new IllegalStateException("Could not sign the test certificate", e);
        }
    }

    private static BigInteger serial() {
        return BigInteger.valueOf(SERIAL.incrementAndGet());
    }
}
