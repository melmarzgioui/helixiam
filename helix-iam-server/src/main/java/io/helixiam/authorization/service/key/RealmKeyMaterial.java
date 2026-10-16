/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Pure key and certificate handling for the realm signing keys ({@code realm_key}): parsing and validating an imported
 * private key and certificate chain, generating keys and PKCS#10 CSRs, the JWK {@code kid}, fingerprints and the
 * deterministic self-signed SAML fallback certificate. No I/O, no logging.
 *
 * <p>Supported: RSA ≥ 2048 bits (RS256, PS256 twin) and EC P-256 (ES256). Every refusal is a {@link KeyImportException}
 * naming the form field; messages never contain key or PEM content.
 */
public final class RealmKeyMaterial {

    public static final String RS256 = "RS256";
    public static final String ES256 = "ES256";

    /** Every refusal of an import names one of these fields (plus the {@link KeyImportException} ones). */
    public static final String ALGORITHM = "algorithm";
    public static final String SUBJECT = "subject";
    public static final String DNS_NAMES = "dnsNames";

    private static final int MIN_RSA_BITS = 2048;
    /** The largest RSA key accepted (signing cost grows with the cube of the size; 4096 is the common ceiling). */
    public static final int MAX_RSA_BITS = 4096;
    private static final BigInteger MIN_RSA_EXPONENT = BigInteger.valueOf(65_537);
    /** One PEM block (any type), optionally surrounded by whitespace, and nothing else. */
    private static final Pattern SINGLE_PEM = Pattern.compile(
            "\\s*-----BEGIN ([A-Z0-9 ]+)-----[A-Za-z0-9+/=\\s:,-]*?-----END \\1-----\\s*");
    private static final java.util.Map<String, org.bouncycastle.asn1.ASN1ObjectIdentifier> SUBJECT_KEYWORDS =
            java.util.Map.of("CN", org.bouncycastle.asn1.x500.style.BCStyle.CN,
                    "O", org.bouncycastle.asn1.x500.style.BCStyle.O,
                    "OU", org.bouncycastle.asn1.x500.style.BCStyle.OU,
                    "C", org.bouncycastle.asn1.x500.style.BCStyle.C,
                    "L", org.bouncycastle.asn1.x500.style.BCStyle.L,
                    "ST", org.bouncycastle.asn1.x500.style.BCStyle.ST,
                    "EMAILADDRESS", org.bouncycastle.asn1.x500.style.BCStyle.EmailAddress,
                    "SERIALNUMBER", org.bouncycastle.asn1.x500.style.BCStyle.SERIALNUMBER,
                    "DC", org.bouncycastle.asn1.x500.style.BCStyle.DC,
                    "UID", org.bouncycastle.asn1.x500.style.BCStyle.UID);
    private static final int GENERATED_RSA_BITS = 2048;
    private static final int MAX_DNS_NAMES = 20;
    private static final Pattern DNS_NAME = Pattern.compile(
            "^(\\*\\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");
    private static final byte[] MATCH_PROBE = "helix-realm-key-match".getBytes(StandardCharsets.US_ASCII);
    private static final String UNSUPPORTED_CURVE = "Unsupported EC curve";
    private static final String NOT_PARSED = "The private key could not be parsed as PEM";
    // Fixed validity window: the self-signed fallback certificate is byte-stable for a stable key.
    private static final Date NOT_BEFORE = Date.from(Instant.parse("2000-01-01T00:00:00Z"));
    private static final Date NOT_AFTER = Date.from(Instant.parse("2099-12-31T23:59:59Z"));
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();

    private RealmKeyMaterial() {
    }

    /** A parsed private key with its public half and its JWS algorithm. */
    public record Parsed(KeyPair keyPair, String algorithm) {
        @Override
        public String toString() {
            return "Parsed[" + algorithm + "]"; // never the key
        }
    }

    // ------------------------------------------------------------------------------------------------ algorithms

    /** The stored algorithm as a JWS name: rc.11 rows say {@code RSA}, which is RS256. */
    public static String normalizeAlgorithm(final String stored) {
        if (stored == null || stored.isBlank() || "RSA".equalsIgnoreCase(stored) || RS256.equalsIgnoreCase(stored)) {
            return RS256;
        }
        if (ES256.equalsIgnoreCase(stored) || "EC".equalsIgnoreCase(stored)) {
            return ES256;
        }
        return stored.toUpperCase(Locale.ROOT);
    }

    /** The requested algorithm for a new key ({@code null}/blank → RS256); anything else is refused. */
    public static String requireSupportedAlgorithm(final String requested) {
        if (requested == null || requested.isBlank()) {
            return RS256;
        }
        final String alg = requested.trim().toUpperCase(Locale.ROOT);
        if (!RS256.equals(alg) && !ES256.equals(alg)) {
            throw new KeyImportException(ALGORITHM, "The algorithm must be RS256 or ES256");
        }
        return alg;
    }

    /** RS256 for an RSA key, ES256 for an EC key. */
    public static String algorithmFor(final PublicKey key) {
        return key instanceof ECPublicKey ? ES256 : RS256;
    }

    /** The JCA signature algorithm a key of {@code alg} signs with (SHA-256 based). */
    public static String jcaSignatureAlgorithm(final String alg) {
        return ES256.equals(normalizeAlgorithm(alg)) ? "SHA256withECDSA" : "SHA256withRSA";
    }

    /** A fresh key pair: RSA-2048 for RS256, EC P-256 for ES256. */
    public static KeyPair generate(final String algorithm) {
        final String alg = requireSupportedAlgorithm(algorithm);
        try {
            if (ES256.equals(alg)) {
                final KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                return g.generateKeyPair();
            }
            final KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(GENERATED_RSA_BITS);
            return g.generateKeyPair();
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Key generation unavailable for " + alg, e);
        }
    }

    /** The stored Base64 SPKI public key and PKCS#8 private key of {@code algorithm} as a key pair. */
    public static KeyPair decode(final String algorithm, final String publicKeyBase64, final String privateKeyBase64) {
        final String jca = ES256.equals(normalizeAlgorithm(algorithm)) ? "EC" : "RSA";
        try {
            final KeyFactory kf = KeyFactory.getInstance(jca);
            final PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
            final PrivateKey priv = privateKeyBase64 == null ? null
                    : kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyBase64)));
            return new KeyPair(pub, priv);
        } catch (final GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Invalid stored " + jca + " key");
        }
    }

    /** Only the public key of a stored row. */
    public static PublicKey decodePublic(final String algorithm, final String publicKeyBase64) {
        return decode(algorithm, publicKeyBase64, null).getPublic();
    }

    // ------------------------------------------------------------------------------------------------ private key

    /**
     * Parses a PEM private key: PKCS#8 ({@code BEGIN PRIVATE KEY}), PKCS#1 ({@code BEGIN RSA PRIVATE KEY}) or SEC1
     * ({@code BEGIN EC PRIVATE KEY}); RSA ≥ 2048 bits or EC P-256. Encrypted PEM is refused.
     */
    public static Parsed parsePrivateKey(final String pem) {
        if (pem == null || pem.isBlank()) {
            throw keyError("A PEM private key is required");
        }
        if (!SINGLE_PEM.matcher(pem).matches()) {
            throw keyError("Paste exactly one PEM private key, with nothing before or after it");
        }
        final Object o;
        try (PEMParser parser = new PEMParser(new StringReader(pem.strip()))) {
            o = parser.readObject();
            if (parser.readObject() != null) {
                throw keyError("Paste exactly one PEM private key, with nothing before or after it");
            }
        } catch (final KeyImportException e) {
            throw e;
        } catch (final IOException | RuntimeException e) {
            throw keyError(NOT_PARSED);
        }
        if (o instanceof PKCS8EncryptedPrivateKeyInfo || o instanceof PEMEncryptedKeyPair) {
            throw keyError("The private key is encrypted; decrypt it first (for example: openssl pkey -in key.pem)");
        }
        final PrivateKeyInfo info;
        if (o instanceof PrivateKeyInfo pkcs8) {
            info = pkcs8;
        } else if (o instanceof PEMKeyPair pair) {
            info = pair.getPrivateKeyInfo();
        } else {
            throw keyError("The private key must be an unencrypted PEM private key (BEGIN PRIVATE KEY, "
                    + "BEGIN RSA PRIVATE KEY or BEGIN EC PRIVATE KEY)");
        }
        final ASN1ObjectIdentifier keyAlg = info.getPrivateKeyAlgorithm().getAlgorithm();
        try {
            if (PKCSObjectIdentifiers.rsaEncryption.equals(keyAlg)) {
                final PrivateKey key = new JcaPEMKeyConverter().getPrivateKey(info);
                if (!(key instanceof RSAPrivateCrtKey crt)) {
                    throw keyError("The RSA private key must include its CRT parameters");
                }
                if (crt.getModulus().bitLength() < MIN_RSA_BITS) {
                    throw keyError("RSA keys must be at least 2048 bits (this one has "
                            + crt.getModulus().bitLength() + ")");
                }
                if (crt.getModulus().bitLength() > MAX_RSA_BITS) {
                    throw keyError("RSA keys can be at most " + MAX_RSA_BITS + " bits (this one has "
                            + crt.getModulus().bitLength() + ")");
                }
                if (crt.getPublicExponent().compareTo(MIN_RSA_EXPONENT) < 0 || !crt.getPublicExponent().testBit(0)) {
                    throw keyError("The RSA public exponent must be an odd number of at least 65537");
                }
                if (crt.getPublicExponent().bitLength() > 32) {
                    throw keyError("The RSA public exponent must fit in 32 bits (65537 is the usual value)");
                }
                final PublicKey pub = KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
                return new Parsed(new KeyPair(pub, key), RS256);
            }
            if (X9ObjectIdentifiers.id_ecPublicKey.equals(keyAlg)) {
                requireP256(info);
                // BouncyCastle reads the curve wherever the encoding carries it (algorithm identifier or the SEC1
                // structure); the key is then re-created as a plain JDK P-256 key.
                final ECPrivateKey bcKey = (ECPrivateKey) new JcaPEMKeyConverter().setProvider(BC).getPrivateKey(info);
                if (!Curve.P_256.equals(Curve.forECParameterSpec(bcKey.getParams()))) {
                    throw keyError(UNSUPPORTED_CURVE + "; use P-256");
                }
                final java.security.AlgorithmParameters ap = java.security.AlgorithmParameters.getInstance("EC");
                ap.init(new ECGenParameterSpec("secp256r1"));
                final java.security.spec.ECParameterSpec p256 = ap.getParameterSpec(java.security.spec.ECParameterSpec.class);
                final PrivateKey key = KeyFactory.getInstance("EC")
                        .generatePrivate(new java.security.spec.ECPrivateKeySpec(bcKey.getS(), p256));
                return new Parsed(new KeyPair(ecPublicFor((ECPrivateKey) key), key), ES256);
            }
        } catch (final KeyImportException e) {
            throw e;
        } catch (final IOException | GeneralSecurityException | RuntimeException e) {
            throw keyError(NOT_PARSED);
        }
        throw keyError("Unsupported key type; use an RSA (2048 bits or more) or EC P-256 key");
    }

    private static void requireP256(final PrivateKeyInfo info) {
        final org.bouncycastle.asn1.ASN1Encodable raw = info.getPrivateKeyAlgorithm().getParameters();
        if (raw == null) {
            throw keyError("The EC private key does not name its curve; export it with its parameters "
                    + "(for example: openssl pkey -in key.pem)");
        }
        final X962Parameters params = X962Parameters.getInstance(raw);
        if (!params.isNamedCurve()) {
            throw keyError(UNSUPPORTED_CURVE + " (explicit curve parameters); use P-256");
        }
        final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
        if (!SECObjectIdentifiers.secp256r1.equals(oid)) {
            final String name = ECNamedCurveTable.getName(oid);
            throw keyError(UNSUPPORTED_CURVE + " " + (name == null ? oid.getId() : name) + "; use P-256");
        }
    }

    private static PublicKey ecPublicFor(final ECPrivateKey key) throws GeneralSecurityException {
        final X9ECParameters x9 = ECNamedCurveTable.getByOID(SECObjectIdentifiers.secp256r1);
        final ECPoint q = x9.getG().multiply(key.getS()).normalize();
        final java.security.spec.ECPoint w = new java.security.spec.ECPoint(
                q.getAffineXCoord().toBigInteger(), q.getAffineYCoord().toBigInteger());
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, key.getParams()));
    }

    // ------------------------------------------------------------------------------------------------ chain

    /** Parses a PEM chain: only {@code CERTIFICATE} blocks, at least one. */
    public static List<X509Certificate> parseChain(final String pem) {
        if (pem == null || pem.isBlank()) {
            throw chainError("A PEM certificate chain is required");
        }
        final List<X509Certificate> certs = new ArrayList<>();
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object o;
            while ((o = parser.readObject()) != null) {
                if (!(o instanceof X509CertificateHolder holder)) {
                    throw chainError("The certificate chain must contain only PEM certificates");
                }
                certs.add(converter.getCertificate(holder));
            }
        } catch (final KeyImportException e) {
            throw e;
        } catch (final IOException | GeneralSecurityException | RuntimeException e) {
            throw chainError("The certificate chain could not be parsed as PEM certificates");
        }
        if (certs.isEmpty()) {
            throw chainError("The certificate chain must contain at least the leaf certificate");
        }
        return certs;
    }

    /**
     * The import rules for a chain of the key {@code publicKey}: the leaf (first) matches the key, has digitalSignature
     * if it has a keyUsage extension, every certificate is valid at {@code now}, and each certificate is issued (DN and
     * signature) by the next one.
     */
    public static void validateChain(final List<X509Certificate> chain, final PublicKey publicKey, final Instant now) {
        if (chain == null || chain.isEmpty()) {
            throw chainError("The certificate chain must contain at least the leaf certificate");
        }
        final X509Certificate leaf = chain.get(0);
        if (!sameKey(leaf.getPublicKey(), publicKey)) {
            throw chainError("The private key does not match the certificate (the first certificate of the chain "
                    + "must be the leaf for this key)");
        }
        final boolean[] usage = leaf.getKeyUsage();
        if (usage != null && (usage.length == 0 || !usage[0])) {
            throw chainError("The leaf certificate's keyUsage must include digitalSignature");
        }
        if (leaf.getBasicConstraints() >= 0) {
            throw chainError("The leaf certificate must not be a CA certificate (basicConstraints CA:true)");
        }
        final Date at = Date.from(now);
        for (int i = 0; i < chain.size(); i++) {
            final X509Certificate c = chain.get(i);
            final String which = i == 0 ? "The leaf certificate" : "The chain is not valid now: certificate " + (i + 1);
            if (at.after(c.getNotAfter())) {
                throw chainError(which + " has expired (notAfter " + c.getNotAfter().toInstant() + ")");
            }
            if (at.before(c.getNotBefore())) {
                throw chainError(which + " is not yet valid (notBefore " + c.getNotBefore().toInstant() + ")");
            }
        }
        for (int i = 1; i < chain.size(); i++) {
            final X509Certificate issuer = chain.get(i);
            if (issuer.getBasicConstraints() < 0) {
                throw chainError("The chain is not valid: certificate " + (i + 1)
                        + " issues certificates but is not a CA certificate (basicConstraints CA:true)");
            }
            final boolean[] ku = issuer.getKeyUsage();
            if (ku != null && (ku.length <= 5 || !ku[5])) {
                throw chainError("The chain is not valid: certificate " + (i + 1)
                        + " issues certificates but its keyUsage lacks keyCertSign");
            }
        }
        for (int i = 0; i + 1 < chain.size(); i++) {
            if (!issuedBy(chain.get(i), chain.get(i + 1))) {
                throw chainError("The certificate chain must be ordered leaf first, each certificate issued by the "
                        + "next one (certificate " + (i + 2) + " did not issue certificate " + (i + 1) + ")");
            }
        }
    }

    /** Proof that {@code privateKey} belongs to {@code publicKey} (sign and verify a probe). */
    public static boolean matches(final PrivateKey privateKey, final PublicKey publicKey) {
        if (privateKey == null || publicKey == null
                || !privateKey.getAlgorithm().equalsIgnoreCase(publicKey.getAlgorithm())) {
            return false;
        }
        final String sigAlg = jcaSignatureAlgorithm(algorithmFor(publicKey));
        try {
            final Signature signer = Signature.getInstance(sigAlg);
            signer.initSign(privateKey);
            signer.update(MATCH_PROBE);
            final byte[] sig = signer.sign();
            final Signature verifier = Signature.getInstance(sigAlg);
            verifier.initVerify(publicKey);
            verifier.update(MATCH_PROBE);
            return verifier.verify(sig);
        } catch (final GeneralSecurityException e) {
            return false;
        }
    }

    /** The chain as published in {@code x5c}: without a trailing self-signed root when there is more than one. */
    public static List<X509Certificate> x5cChain(final List<X509Certificate> chain) {
        final List<X509Certificate> out = new ArrayList<>(chain);
        if (out.size() > 1 && isSelfSigned(out.get(out.size() - 1))) {
            out.remove(out.size() - 1);
        }
        return out;
    }

    public static boolean isSelfSigned(final X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())
                && verifiesWith(cert, cert.getPublicKey());
    }

    public static String chainToPem(final List<X509Certificate> chain) {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            for (final X509Certificate cert : chain) {
                writer.writeObject(cert);
            }
        } catch (final IOException e) {
            throw new IllegalStateException("Could not encode the certificate chain", e);
        }
        return out.toString();
    }

    public static String certificatePem(final X509Certificate cert) {
        return chainToPem(List.of(cert));
    }

    // ------------------------------------------------------------------------------------------------ CSR

    /**
     * A PEM PKCS#10 request for {@code keyPair}: the subject DN (RFC 4514), a keyUsage=digitalSignature extension
     * request and, when given, a subjectAltName with the DNS names; signed SHA256withRSA / SHA256withECDSA.
     */
    public static String csr(final KeyPair keyPair, final String algorithm, final String subject,
                             final List<String> dnsNames) {
        final X500Name name = parseSubject(subject);
        final List<String> names = validateDnsNames(dnsNames);
        try {
            final JcaPKCS10CertificationRequestBuilder builder =
                    new JcaPKCS10CertificationRequestBuilder(name, keyPair.getPublic());
            final ExtensionsGenerator ext = new ExtensionsGenerator();
            ext.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            if (!names.isEmpty()) {
                final GeneralName[] gn = names.stream().map(n -> new GeneralName(GeneralName.dNSName, n))
                        .toArray(GeneralName[]::new);
                ext.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(gn));
            }
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate());
            final ContentSigner signer = new JcaContentSignerBuilder(jcaSignatureAlgorithm(algorithm))
                    .build(keyPair.getPrivate());
            final PKCS10CertificationRequest csr = builder.build(signer);
            final StringWriter out = new StringWriter();
            try (JcaPEMWriter w = new JcaPEMWriter(out)) {
                w.writeObject(csr);
            }
            return out.toString();
        } catch (final Exception e) {
            throw new IllegalStateException("Could not build the certificate signing request");
        }
    }

    /**
     * An RFC 4514 subject DN with at least one attribute, using only the keywords CN, O, OU, C, L, ST, emailAddress,
     * SERIALNUMBER, DC and UID (no raw OIDs, no {@code #hex} values).
     */
    public static X500Name parseSubject(final String subject) {
        if (subject == null || subject.isBlank()) {
            throw new KeyImportException(SUBJECT, "A subject DN is required (for example CN=idp.example.com, O=Example)");
        }
        final String bad = "The subject must be a distinguished name such as CN=idp.example.com, O=Example, C=NL, "
                + "using CN, O, OU, C, L, ST, emailAddress, SERIALNUMBER, DC or UID";
        if (subject.length() > 1024) {
            throw new KeyImportException(SUBJECT, bad);
        }
        final org.bouncycastle.asn1.x500.X500NameBuilder builder =
                new org.bouncycastle.asn1.x500.X500NameBuilder(org.bouncycastle.asn1.x500.style.BCStyle.INSTANCE);
        for (final String rdn : splitUnescaped(subject.trim(), ',')) {
            final List<String> avas = splitUnescaped(rdn, '+');
            if (avas.size() != 1) {
                throw new KeyImportException(SUBJECT, bad + " (no multi-valued RDNs)");
            }
            final String ava = avas.get(0);
            final int eq = ava.indexOf('=');
            if (eq <= 0) {
                throw new KeyImportException(SUBJECT, bad);
            }
            final org.bouncycastle.asn1.ASN1ObjectIdentifier type =
                    SUBJECT_KEYWORDS.get(ava.substring(0, eq).trim().toUpperCase(Locale.ROOT));
            final String raw = ava.substring(eq + 1).trim();
            final String value = unescape(raw);
            if (type == null || value.isEmpty() || raw.startsWith("#")) {
                throw new KeyImportException(SUBJECT, bad);
            }
            // Explicit ASN.1 string types: BouncyCastle's addRDN(oid, String) would parse a value starting with '#'
            // (even one decoded from an escape) as raw hex DER.
            builder.addRDN(type, attributeValue(type, value, bad));
        }
        try {
            final X500Name name = builder.build();
            if (name.getRDNs().length == 0) {
                throw new KeyImportException(SUBJECT, bad);
            }
            name.getEncoded();
            return name;
        } catch (final KeyImportException e) {
            throw e;
        } catch (final IOException | RuntimeException e) {
            throw new KeyImportException(SUBJECT, bad);
        }
    }

    private static org.bouncycastle.asn1.ASN1Encodable attributeValue(final org.bouncycastle.asn1.ASN1ObjectIdentifier type,
                                                                       final String value, final String bad) {
        if (org.bouncycastle.asn1.x500.style.BCStyle.C.equals(type)) {
            if (!value.matches("[A-Za-z]{2}")) {
                throw new KeyImportException(SUBJECT, "The country (C) must be a two-letter code such as NL");
            }
            return new org.bouncycastle.asn1.DERPrintableString(value.toUpperCase(Locale.ROOT));
        }
        if (org.bouncycastle.asn1.x500.style.BCStyle.SERIALNUMBER.equals(type)) {
            if (!org.bouncycastle.asn1.DERPrintableString.isPrintableString(value)) {
                throw new KeyImportException(SUBJECT, bad);
            }
            return new org.bouncycastle.asn1.DERPrintableString(value);
        }
        if (org.bouncycastle.asn1.x500.style.BCStyle.EmailAddress.equals(type)
                || org.bouncycastle.asn1.x500.style.BCStyle.DC.equals(type)) {
            if (!org.bouncycastle.asn1.DERIA5String.isIA5String(value)) {
                throw new KeyImportException(SUBJECT, bad);
            }
            return new org.bouncycastle.asn1.DERIA5String(value);
        }
        return new org.bouncycastle.asn1.DERUTF8String(value);
    }

    /** Splits on {@code sep} outside backslash escapes and double quotes. */
    private static List<String> splitUnescaped(final String text, final char sep) {
        final List<String> out = new ArrayList<>();
        final StringBuilder cur = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < text.length(); i++) {
            final char c = text.charAt(i);
            if (c == '\\' && i + 1 < text.length()) {
                cur.append(c).append(text.charAt(++i));
            } else if (c == '"') {
                quoted = !quoted;
                cur.append(c);
            } else if (c == sep && !quoted) {
                out.add(cur.toString());
                cur.setLength(0);
            } else if (c == ';' && !quoted && sep == ',') {
                throw new KeyImportException(SUBJECT, "Separate the subject's attributes with commas");
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }

    /** RFC 4514 unescaping: {@code \\c} is c, {@code \\XX} a UTF-8 byte in hex. */
    private static String unescape(final String value) {
        String v = value;
        if (v.length() >= 2 && v.startsWith("\"") && v.endsWith("\"")) {
            v = v.substring(1, v.length() - 1);
        }
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < v.length(); i++) {
            final char c = v.charAt(i);
            if (c == '\\' && isHex(v, i + 1) && isHex(v, i + 2)) {
                out.write(Integer.parseInt(v.substring(i + 1, i + 3), 16));
                i += 2;
            } else if (c == '\\' && i + 1 < v.length()) {
                out.writeBytes(String.valueOf(v.charAt(++i)).getBytes(StandardCharsets.UTF_8));
            } else {
                out.writeBytes(String.valueOf(c).getBytes(StandardCharsets.UTF_8));
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static boolean isHex(final String s, final int i) {
        return i < s.length() && Character.digit(s.charAt(i), 16) >= 0;
    }

    private static List<String> validateDnsNames(final List<String> dnsNames) {
        if (dnsNames == null) {
            return List.of();
        }
        final List<String> out = new ArrayList<>();
        for (final String raw : dnsNames) {
            if (raw == null || raw.isBlank()) {
                continue;
            }
            final String n = raw.trim();
            if (n.length() > 253 || !DNS_NAME.matcher(n).matches()) {
                throw new KeyImportException(DNS_NAMES, "Not a valid DNS name: " + n.substring(0, Math.min(64, n.length())));
            }
            out.add(n);
        }
        if (out.size() > MAX_DNS_NAMES) {
            throw new KeyImportException(DNS_NAMES, "At most " + MAX_DNS_NAMES + " DNS names");
        }
        return out;
    }

    // ------------------------------------------------------------------------------------------------ ids, digests

    /**
     * The JWK {@code kid}: for RSA the modulus-derived id HelixIAM has always used (so tokens issued before keep
     * verifying), for EC the RFC 7638 thumbprint.
     */
    public static String kid(final PublicKey publicKey) {
        try {
            if (publicKey instanceof RSAPublicKey rsa) {
                return Base64.getEncoder().encodeToString(
                        MessageDigest.getInstance("SHA-256").digest(rsa.getModulus().toByteArray()));
            }
            if (publicKey instanceof ECPublicKey ec) {
                return new ECKey.Builder(Curve.forECParameterSpec(ec.getParams()), ec).build()
                        .computeThumbprint().toString();
            }
        } catch (final Exception e) {
            throw new IllegalStateException("Could not derive the key id", e);
        }
        throw new IllegalArgumentException("Unsupported public key type");
    }

    /** SHA-256 of the certificate DER, upper-case hex pairs separated by colons. */
    public static String fingerprint(final X509Certificate cert) {
        try {
            return colonHex(MessageDigest.getInstance("SHA-256").digest(cert.getEncoded()));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** SHA-256 of the public key SPKI (the fingerprint of a key without a certificate). */
    public static String publicKeyFingerprint(final PublicKey key) {
        try {
            return colonHex(MessageDigest.getInstance("SHA-256").digest(key.getEncoded()));
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String colonHex(final byte[] digest) {
        return HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    }

    // ------------------------------------------------------------------------------------------------ self-signed

    /**
     * The deterministic self-signed certificate HelixIAM publishes for a key without a certificate (SAML): subject
     * {@code CN=helix-idp-<realm>}, serial from the public key, validity 2000–2099, signed by the key itself
     * (SHA256withRSA, or deterministic RFC 6979 ECDSA for EC so the bytes stay stable).
     */
    public static X509Certificate selfSigned(final String realm, final KeyPair keyPair) {
        try {
            final PublicKey publicKey = keyPair.getPublic();
            final X500Principal dn = new X500Principal("CN=helix-idp-" + realm);
            final BigInteger serial = new BigInteger(1,
                    MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
            final JcaX509v3CertificateBuilder builder =
                    new JcaX509v3CertificateBuilder(dn, serial, NOT_BEFORE, NOT_AFTER, dn, publicKey);
            final ContentSigner signer = publicKey instanceof ECPublicKey
                    ? new DeterministicEcdsaSigner(keyPair.getPrivate())
                    : new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        } catch (final Exception e) {
            throw new IllegalStateException("Failed to build the self-signed certificate for realm '" + realm + "'", e);
        }
    }

    /** ecdsa-with-SHA256 with RFC 6979 deterministic nonces (BouncyCastle "SHA256withECDDSA"). */
    private static final class DeterministicEcdsaSigner implements ContentSigner {
        private final java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        private final PrivateKey key;

        DeterministicEcdsaSigner(final PrivateKey key) {
            this.key = key;
        }

        @Override
        public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
            return new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
        }

        @Override
        public java.io.OutputStream getOutputStream() {
            return buffer;
        }

        @Override
        public byte[] getSignature() {
            try {
                final Signature s = Signature.getInstance("SHA256withECDDSA", BC);
                s.initSign(key);
                s.update(buffer.toByteArray());
                return s.sign();
            } catch (final GeneralSecurityException e) {
                throw new IllegalStateException("Deterministic ECDSA unavailable", e);
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ helpers

    private static boolean sameKey(final PublicKey a, final PublicKey b) {
        return a != null && b != null && java.util.Arrays.equals(a.getEncoded(), b.getEncoded());
    }

    private static boolean issuedBy(final X509Certificate cert, final X509Certificate issuer) {
        return cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                && verifiesWith(cert, issuer.getPublicKey());
    }

    private static boolean verifiesWith(final X509Certificate cert, final PublicKey key) {
        try {
            cert.verify(key);
            return true;
        } catch (final GeneralSecurityException e) {
            return false;
        }
    }

    private static KeyImportException keyError(final String message) {
        return new KeyImportException(KeyImportException.PRIVATE_KEY, message);
    }

    private static KeyImportException chainError(final String message) {
        return new KeyImportException(KeyImportException.CHAIN, message);
    }
}
