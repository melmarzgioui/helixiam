/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import io.helixiam.common.log.LogSafe;
import io.helixiam.common.startup.DeploymentProfile;
import io.helixiam.persistence.security.AttributeEncryption;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.nimbusds.jose.jwk.Curve;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The software store of {@link RealmSigningKeys}: verifier access-certificate keys in the {@code verifier_signing_key}
 * table (Flyway V76), the private key as PKCS#8 PEM encrypted at rest with {@code DB_ENCRYPTION}
 * ({@link AttributeEncryption}, AES-GCM), the chain as public PEM.
 *
 * <h2>Key references</h2>
 * {@code software:<realm>/<name>}, name {@code [A-Za-z0-9._-]{1,64}}. {@link #resolve} only looks in the realm it is
 * given: a reference naming another realm is "not found" ({@link NoSuchElementException}), exactly like a missing key,
 * so a reference never crosses realms. {@code pkcs11:} and {@code kms:} references are the HSM / KMS seam and are
 * refused with {@link UnsupportedOperationException} ("not supported yet"); any other scheme is an
 * {@link IllegalArgumentException}.
 *
 * <h2>Algorithms</h2>
 * EC only; the curve <em>identity</em> (named-curve OID / Nimbus {@link Curve}, never the field size) decides the JWS
 * algorithm: P-256 → ES256, P-384 → ES384, P-521 → ES512; secp256k1, brainpool and explicit parameters are refused. <b>RSA keys are refused
 * at any size</b>: HAIP / OpenID4VP request signing uses ECDSA, the feature does not need RSA, and refusing it keeps
 * the "RSA ≥ 2048" rule trivially true.
 *
 * <h2>Import checks</h2>
 * The private key must match the leaf (first) certificate's public key; the chain is leaf first (every certificate is
 * issued and signed by the next one); the leaf must be currently valid (not expired, not yet valid) and <b>must not be
 * self-signed</b> (HAIP: the certificate signing the request object must not be self-signed), judged by its signature
 * verifying with its own key, whatever its issuer DN says. A trailing self-signed
 * certificate (the trust anchor) is dropped before storing: the {@code x5c} chain must not contain it. Names are
 * unique per realm; importing an existing name is refused (keys are immutable; rotate by importing a new name).
 *
 * <h2>Encryption at rest</h2>
 * Without {@code DB_ENCRYPTION} the import is refused unless the {@code dev} profile is active ({@link DeploymentProfile});
 * in dev the key is stored in plaintext with a warning.
 *
 * <p>Key material is never logged and never echoed in exception messages; realm and name are logged through
 * {@link LogSafe#sanitize}.
 */
@Component
public class SoftwareRealmSigningKeys implements RealmSigningKeys {

    private static final Logger LOG = LogManager.getLogger(SoftwareRealmSigningKeys.class);

    static final String SOFTWARE_SCHEME = "software:";
    private static final Pattern NAME = Pattern.compile("[A-Za-z0-9._-]{1,64}");
    private static final String ENCRYPTION_PROBE = "helix-encryption-probe";
    private static final String UNSUPPORTED_CURVE = "Unsupported EC curve";
    private static final Set<ASN1ObjectIdentifier> ALLOWED_CURVES = Set.of(SECObjectIdentifiers.secp256r1,
            SECObjectIdentifiers.secp384r1, SECObjectIdentifiers.secp521r1);
    private static final byte[] MATCH_PROBE = "helix-verifier-key-match".getBytes(StandardCharsets.US_ASCII);

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final TransactionTemplate readTx;
    private final AttributeEncryption encryption;
    private final DeploymentProfile profile;
    private final boolean encrypted;

    @Autowired
    public SoftwareRealmSigningKeys(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                                    @Value("${database.encryption:#{null}}") final String encryptionKey,
                                    final DeploymentProfile profile) {
        this(jdbc, transactions, new AttributeEncryption(encryptionKey), profile);
    }

    public SoftwareRealmSigningKeys(final JdbcTemplate jdbc, final PlatformTransactionManager transactions,
                                    final AttributeEncryption encryption, final DeploymentProfile profile) {
        this.profile = profile;
        this.jdbc = jdbc;
        // The pool has auto-commit off: every write commits in its own transaction.
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.readTx = new TransactionTemplate(transactions);
        this.readTx.setReadOnly(true);
        this.encryption = encryption;
        // AttributeEncryption without a key passes values through unchanged.
        this.encrypted = !ENCRYPTION_PROBE.equals(encryption.convertToDatabaseColumn(ENCRYPTION_PROBE));
    }

    // ------------------------------------------------------------------------------------------------ resolve

    @Override
    public SigningKeyHandle resolve(final String realmId, final String keyRef) {
        requireRealm(realmId);
        if (keyRef == null || keyRef.isBlank()) {
            throw new IllegalArgumentException("A key reference is required");
        }
        final String lower = keyRef.toLowerCase(Locale.ROOT);
        if (lower.startsWith("pkcs11:") || lower.startsWith("kms:")) {
            throw new UnsupportedOperationException("Key reference scheme '" + lower.substring(0, lower.indexOf(':') + 1)
                    + "' (HSM / KMS) is not supported yet; import the key into the software store (software:)");
        }
        if (!keyRef.startsWith(SOFTWARE_SCHEME)) {
            throw new IllegalArgumentException("Unsupported key reference; expected software:<realm>/<name>");
        }
        final String path = keyRef.substring(SOFTWARE_SCHEME.length());
        final int slash = path.lastIndexOf('/');
        final String refRealm = slash < 0 ? "" : path.substring(0, slash);
        final String name = path.substring(slash + 1);
        if (!refRealm.equals(realmId) || !NAME.matcher(name).matches()) {
            throw notFound(realmId, keyRef);
        }
        final List<Row> rows = readTx.execute(s -> jdbc.query(
                "SELECT alg, private_key, certificate_chain_pem FROM verifier_signing_key WHERE realm_id = ? AND name = ?",
                (rs, i) -> new Row(rs.getString(1), rs.getString(2), rs.getString(3)), realmId, name));
        if (rows == null || rows.isEmpty()) {
            throw notFound(realmId, keyRef);
        }
        final Row row = rows.get(0);
        final PrivateKey privateKey = parsePrivateKey(encryption.convertToEntityAttribute(row.privateKey()));
        if (!(privateKey instanceof ECPrivateKey ec)) {
            throw new IllegalStateException("Stored verifier signing key is not an EC key");
        }
        final JWSAlgorithm alg = JWSAlgorithm.parse(row.alg());
        if (!alg.equals(algorithmFor(ec))) {
            throw new IllegalStateException("Stored verifier signing key algorithm does not match its curve");
        }
        try {
            return new Handle(keyRef, alg, List.copyOf(parseChain(row.chainPem())),
                    new RestrictedSigner(new ECDSASigner(ec), alg));
        } catch (final JOSEException e) {
            throw new IllegalStateException("Stored verifier signing key cannot sign", e);
        }
    }

    /**
     * A handle over a raw PEM private key and its PEM chain (leaf first), for the dev-only wallet access key
     * ({@code accessCertificatePrivateKey}, which never enters the store). It signs through the same restricted signer
     * as a stored key, so the private key is never exposed; {@code label} is its {@link SigningKeyHandle#keyRef()}.
     * Nothing beyond parsing is checked here: the caller validates the chain and the key/leaf match first.
     *
     * @throws IllegalArgumentException when the key or the chain cannot be parsed, or the key is not EC P-256/384/521
     *                                  (field-safe message, never the PEM)
     */
    public static SigningKeyHandle softwareHandle(final String label, final String privateKeyPem,
                                                  final String certificateChainPem) {
        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            throw new IllegalArgumentException("A PEM private key is required");
        }
        final PrivateKey privateKey = parsePrivateKey(privateKeyPem);
        if (!(privateKey instanceof ECPrivateKey ec)) {
            throw new IllegalArgumentException("Only EC P-256, P-384 or P-521 private keys are supported");
        }
        final JWSAlgorithm alg = algorithmFor(ec);
        final List<X509Certificate> chain = List.copyOf(parseCertificateChain(certificateChainPem));
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("A certificate chain is required");
        }
        try {
            return new Handle(label, alg, chain, new RestrictedSigner(new ECDSASigner(ec), alg));
        } catch (final JOSEException e) {
            throw new IllegalArgumentException("The private key cannot sign");
        }
    }

    private static NoSuchElementException notFound(final String realmId, final String keyRef) {
        LOG.debug("Verifier signing key not found realm={} ref={}", LogSafe.sanitize(realmId), LogSafe.sanitize(keyRef));
        return new NoSuchElementException("Signing key not found in this realm");
    }

    // ------------------------------------------------------------------------------------------------ import

    @Override
    public String importKey(final String realmId, final String name, final String privateKeyPem,
                            final String certificateChainPem) {
        requireRealm(realmId);
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("Key name must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'");
        }
        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            throw new IllegalArgumentException("A PEM private key is required");
        }
        if (certificateChainPem == null || certificateChainPem.isBlank()) {
            throw new IllegalArgumentException("A PEM certificate chain is required");
        }
        if (!encrypted) {
            if (!profile.isDev()) {
                throw new IllegalArgumentException("Database encryption is not configured: set DB_ENCRYPTION before "
                        + "importing a verifier signing key");
            }
            LOG.warn("DB_ENCRYPTION is not set: storing verifier signing key realm={} name={} UNENCRYPTED (dev profile)",
                    LogSafe.sanitize(realmId), LogSafe.sanitize(name));
        }
        final PrivateKey privateKey = parsePrivateKey(privateKeyPem);
        if ("RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("RSA keys are not supported for verifier access certificates; "
                    + "use an EC P-256, P-384 or P-521 key");
        }
        if (!(privateKey instanceof ECPrivateKey ec)) {
            throw new IllegalArgumentException("Unsupported private key type " + privateKey.getAlgorithm()
                    + "; use an EC P-256, P-384 or P-521 key");
        }
        final JWSAlgorithm alg = algorithmFor(ec);
        final List<X509Certificate> chain = validateChain(parseChain(certificateChainPem), ec, alg);

        final String encrypted = encryption.convertToDatabaseColumn(toPkcs8Pem(privateKey));
        try {
            tx.executeWithoutResult(s -> jdbc.update("INSERT INTO verifier_signing_key (realm_id, name, alg, "
                    + "private_key, certificate_chain_pem) VALUES (?, ?, ?, ?, ?)", realmId, name, alg.getName(),
                    encrypted, toPem(chain)));
        } catch (final DuplicateKeyException e) {
            throw new IllegalArgumentException("A signing key named '" + name + "' already exists in this realm");
        }
        LOG.info("Imported verifier signing key realm={} name={} alg={} subject={}", LogSafe.sanitize(realmId),
                LogSafe.sanitize(name), alg, LogSafe.sanitize(chain.get(0).getSubjectX500Principal().getName()));
        return SOFTWARE_SCHEME + realmId + "/" + name;
    }

    /** Leaf-first chain checks; returns the chain to store (without a trailing trust anchor). */
    private static List<X509Certificate> validateChain(final List<X509Certificate> parsed, final ECPrivateKey key,
                                                       final JWSAlgorithm alg) {
        final X509Certificate leaf = parsed.get(0);
        if (!matches(key, leaf.getPublicKey(), alg)) {
            throw new IllegalArgumentException("The private key does not match the certificate (the first certificate "
                    + "of the chain must be the leaf for this key)");
        }
        checkLeafValidity(leaf);
        if (verifiesWithOwnKey(leaf)) { // by key alone: an issuer DN != subject must not hide it
            throw new IllegalArgumentException("The verifier access certificate must not be self-signed (HAIP); "
                    + "import a certificate issued by a CA, with its chain");
        }
        checkLeafFirstOrder(parsed);
        final List<X509Certificate> stored = new ArrayList<>(parsed);
        if (stored.size() > 1 && isSelfSigned(stored.get(stored.size() - 1))) {
            stored.remove(stored.size() - 1); // the trust anchor never goes into x5c
        }
        return stored;
    }

    // ------------------------------------------------------------------------------------------------ shared checks

    /**
     * The HAIP "must not be self-signed" test used by {@link #importKey}: {@code cert}'s signature verifies with its own
     * public key, whatever its issuer DN says. Also used to validate a wallet provider's configured access certificate.
     */
    public static boolean verifiesWithOwnKey(final X509Certificate cert) {
        return verifiesWith(cert, cert.getPublicKey());
    }

    /**
     * The import's validity check: the leaf is currently valid.
     *
     * @throws IllegalArgumentException "The leaf certificate has expired (notAfter …)" or "… is not yet valid (notBefore
     *                                  …)"
     */
    public static void checkLeafValidity(final X509Certificate leaf) {
        try {
            leaf.checkValidity();
        } catch (final CertificateExpiredException e) {
            throw new IllegalArgumentException("The leaf certificate has expired (notAfter " + leaf.getNotAfter() + ")");
        } catch (final CertificateNotYetValidException e) {
            throw new IllegalArgumentException("The leaf certificate is not yet valid (notBefore "
                    + leaf.getNotBefore() + ")");
        }
    }

    /**
     * The import's order check: the chain is leaf first, each certificate issued (DN and signature) by the next one.
     *
     * @throws IllegalArgumentException naming the first pair that is out of order
     */
    public static void checkLeafFirstOrder(final List<X509Certificate> chain) {
        for (int i = 0; i + 1 < chain.size(); i++) {
            if (!issuedBy(chain.get(i), chain.get(i + 1))) {
                throw new IllegalArgumentException("The certificate chain must be ordered leaf first, each certificate "
                        + "issued by the next one (certificate " + (i + 2) + " did not issue certificate " + (i + 1) + ")");
            }
        }
    }

    /** A root: subject equals issuer and the signature verifies with its own key. x5c never carries one. */
    public static boolean isSelfSigned(final X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())
                && verifiesWith(cert, cert.getPublicKey());
    }

    /**
     * Parses a PEM certificate chain with the import rules (only {@code CERTIFICATE} blocks, at least one).
     *
     * @throws IllegalArgumentException with a field-safe message (never PEM content or parser detail)
     */
    public static List<X509Certificate> parseCertificateChain(final String pem) {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("A PEM certificate chain is required");
        }
        return parseChain(pem);
    }

    /**
     * Whether the PEM private key (PKCS#8 or SEC1, EC P-256/P-384/P-521) belongs to {@code publicKey}, proven by
     * signing and verifying a probe, as {@link #importKey} does.
     *
     * @throws IllegalArgumentException when the key cannot be parsed or is not an allowed EC key (field-safe message)
     */
    public static boolean privateKeyMatches(final String privateKeyPem, final PublicKey publicKey) {
        if (privateKeyPem == null || privateKeyPem.isBlank()) {
            throw new IllegalArgumentException("A PEM private key is required");
        }
        final PrivateKey privateKey = parsePrivateKey(privateKeyPem);
        if (!(privateKey instanceof ECPrivateKey ec)) {
            throw new IllegalArgumentException("Only EC P-256, P-384 or P-521 private keys are supported");
        }
        return matches(ec, publicKey, algorithmFor(ec));
    }

    // ------------------------------------------------------------------------------------------------ crypto helpers

    static JWSAlgorithm algorithmFor(final ECPrivateKey key) {
        final Curve curve = Curve.forECParameterSpec(key.getParams());
        if (Curve.P_256.equals(curve)) {
            return JWSAlgorithm.ES256;
        }
        if (Curve.P_384.equals(curve)) {
            return JWSAlgorithm.ES384;
        }
        if (Curve.P_521.equals(curve)) {
            return JWSAlgorithm.ES512;
        }
        throw new IllegalArgumentException(UNSUPPORTED_CURVE + (curve == null ? "" : " " + curve.getName())
                + "; use P-256, P-384 or P-521");
    }

    /** Sign-and-verify proof that the private key belongs to the certificate's public key. */
    private static boolean matches(final ECPrivateKey privateKey, final PublicKey publicKey, final JWSAlgorithm alg) {
        if (!(publicKey instanceof ECPublicKey)) {
            return false;
        }
        final String sigAlg = "SHA" + alg.getName().substring(2) + "withECDSA";
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

    /** PKCS#8 ({@code BEGIN PRIVATE KEY}) or SEC1 ({@code BEGIN EC PRIVATE KEY}); errors never echo the input. */
    private static PrivateKey parsePrivateKey(final String pem) {
        final Object o;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            o = parser.readObject();
        } catch (final IOException | RuntimeException e) {
            throw new IllegalArgumentException("The private key could not be parsed as PEM");
        }
        final PrivateKeyInfo info;
        try {
            if (o instanceof PrivateKeyInfo pkcs8) {
                info = pkcs8;
            } else if (o instanceof PEMKeyPair pair) {
                info = pair.getPrivateKeyInfo(); // the public part may be absent
            } else {
                throw new IllegalArgumentException("The private key must be an unencrypted PEM private key "
                        + "(BEGIN PRIVATE KEY or BEGIN EC PRIVATE KEY)");
            }
            requireAllowedCurve(info);
            return new JcaPEMKeyConverter().getPrivateKey(info);
        } catch (final IllegalArgumentException e) {
            if (e.getMessage() != null && (e.getMessage().startsWith("The private key must")
                    || e.getMessage().startsWith(UNSUPPORTED_CURVE))) {
                throw e;
            }
            throw new IllegalArgumentException("The private key could not be parsed as PEM");
        } catch (final IOException | RuntimeException e) {
            throw new IllegalArgumentException("The private key could not be parsed as PEM");
        }
    }

    /**
     * Curve identity, not field size: an EC key must name P-256, P-384 or P-521 (secp256k1 and brainpool share field
     * sizes with them and are refused). Checked on the encoded OID, before any JCA provider sees the key.
     */
    private static void requireAllowedCurve(final PrivateKeyInfo info) {
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(info.getPrivateKeyAlgorithm().getAlgorithm())) {
            return; // RSA etc.: refused later with its own message
        }
        final X962Parameters params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        if (!params.isNamedCurve()) {
            throw new IllegalArgumentException(UNSUPPORTED_CURVE + " (explicit curve parameters); "
                    + "use P-256, P-384 or P-521");
        }
        final ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
        if (!ALLOWED_CURVES.contains(oid)) {
            final String name = ECNamedCurveTable.getName(oid);
            throw new IllegalArgumentException(UNSUPPORTED_CURVE + " " + (name == null ? oid.getId() : name)
                    + "; use P-256, P-384 or P-521");
        }
    }

    private static List<X509Certificate> parseChain(final String pem) {
        final List<X509Certificate> certs = new ArrayList<>();
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object o;
            while ((o = parser.readObject()) != null) {
                if (!(o instanceof X509CertificateHolder holder)) {
                    throw new IllegalArgumentException("The certificate chain must contain only PEM certificates");
                }
                certs.add(converter.getCertificate(holder));
            }
        } catch (final IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("The certificate chain could not be parsed as PEM certificates");
        } catch (final RuntimeException e) {
            // BouncyCastle signals some malformed input (base64 / ASN.1) with runtime exceptions (DecoderException,
            // IllegalArgumentException, ...): the same documented error, never a BC message.
            if (e instanceof IllegalArgumentException iae && iae.getMessage() != null
                    && iae.getMessage().startsWith("The certificate chain must")) {
                throw iae;
            }
            throw new IllegalArgumentException("The certificate chain could not be parsed as PEM certificates");
        }
        if (certs.isEmpty()) {
            throw new IllegalArgumentException("The certificate chain must contain at least the leaf certificate");
        }
        return certs;
    }

    private static String toPkcs8Pem(final PrivateKey key) {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(new JcaPKCS8Generator(key, null));
        } catch (final IOException e) {
            throw new IllegalStateException("Could not encode the private key");
        }
        return out.toString();
    }

    private static String toPem(final List<X509Certificate> chain) {
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

    private static void requireRealm(final String realmId) {
        if (realmId == null || realmId.isBlank() || realmId.indexOf('/') >= 0) {
            throw new IllegalArgumentException("A realm id is required");
        }
    }

    private record Row(String alg, String privateKey, String chainPem) {
    }

    // ------------------------------------------------------------------------------------------------ handle / signer

    /** The resolved key; its {@code toString} names the reference only. */
    private record Handle(String keyRef, JWSAlgorithm algorithm, List<X509Certificate> certificateChain,
                          JWSSigner signer) implements SigningKeyHandle {
        @Override
        public String toString() {
            return "SigningKeyHandle[" + keyRef + ", " + algorithm + "]";
        }
    }

    /**
     * Delegates to a Nimbus {@link ECDSASigner} but hides it (its {@code getPrivateKey()} is public) and signs only
     * with the key's own algorithm.
     */
    private static final class RestrictedSigner implements JWSSigner {
        private final ECDSASigner delegate;
        private final JWSAlgorithm alg;

        RestrictedSigner(final ECDSASigner delegate, final JWSAlgorithm alg) {
            this.delegate = delegate;
            this.alg = alg;
        }

        @Override
        public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
            if (!alg.equals(header.getAlgorithm())) {
                throw new JOSEException("This key signs only with " + alg + ", not " + header.getAlgorithm());
            }
            return delegate.sign(header, signingInput);
        }

        @Override
        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
            return Set.of(alg);
        }

        @Override
        public JCAContext getJCAContext() {
            return delegate.getJCAContext();
        }

        @Override
        public String toString() {
            return "JWSSigner[" + alg + "]";
        }
    }
}
