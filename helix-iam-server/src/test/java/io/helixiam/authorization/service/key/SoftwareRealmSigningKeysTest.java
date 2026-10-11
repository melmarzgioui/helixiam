/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import io.helixiam.e2e.AbstractE2eTest;
import io.helixiam.e2e.E2eSeed;
import io.helixiam.persistence.security.AttributeEncryption;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Task 5: {@link SoftwareRealmSigningKeys} — the verifier access-certificate key store. Runs against the shared e2e
 * context (so both the Flyway path and, with {@code -Dhelix.e2e.schema=sql-init}, the schema.sql path create the
 * {@code verifier_signing_key} table). Test PKI (CA → leaf) is generated with BouncyCastle.
 */
class SoftwareRealmSigningKeysTest extends AbstractE2eTest {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    private RealmSigningKeys keys;
    private JdbcTemplate jdbc;
    private String realm;

    @BeforeEach
    void setUp() {
        keys = context.getBean(RealmSigningKeys.class);
        jdbc = context.getBean(JdbcTemplate.class);
        realm = E2eSeed.unique("vkeys");
    }

    // ---------------------------------------------------------------- happy paths

    @Test
    void importP256_resolve_signsJwsThatVerifiesWithTheLeafKey() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");

        final String ref = keys.importKey(realm, "eudi-access-2026", pem(pki.leafKey.getPrivate()),
                pem(pki.leaf) + pem(pki.ca));
        assertThat(ref).isEqualTo("software:" + realm + "/eudi-access-2026");

        final SigningKeyHandle handle = keys.resolve(realm, ref);
        assertThat(handle.keyRef()).isEqualTo(ref);
        assertThat(handle.algorithm()).isEqualTo(JWSAlgorithm.ES256);
        // Leaf first, the trust anchor (self-signed CA) is not part of the chain.
        assertThat(handle.certificateChain()).containsExactly(pki.leaf);
        assertThat(handle.signer().supportedJWSAlgorithms()).containsExactly(JWSAlgorithm.ES256);

        final JWSObject jws = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("oauth-authz-req+jwt")).build(), new Payload("{\"nonce\":\"n\"}"));
        jws.sign(handle.signer());
        final JWSObject parsed = JWSObject.parse(jws.serialize());
        assertThat(parsed.verify(new ECDSAVerifier((ECPublicKey) pki.leaf.getPublicKey()))).isTrue();
    }

    @Test
    void curveDecidesTheAlgorithm_p384_es384_p521_es512_withIntermediate() throws Exception {
        final Pki p384 = Pki.ec("secp384r1", "SHA384withECDSA");
        final SigningKeyHandle h384 = keys.resolve(realm,
                keys.importKey(realm, "k384", pem(p384.leafKey.getPrivate()), pem(p384.leaf)));
        assertThat(h384.algorithm()).isEqualTo(JWSAlgorithm.ES384);

        final Pki p521 = Pki.ec("secp521r1", "SHA512withECDSA");
        final SigningKeyHandle h521 = keys.resolve(realm,
                keys.importKey(realm, "k521", pem(p521.leafKey.getPrivate()), pem(p521.leaf) + pem(p521.intermediate)));
        assertThat(h521.algorithm()).isEqualTo(JWSAlgorithm.ES512);
        assertThat(h521.certificateChain()).containsExactly(p521.leaf, p521.intermediate);

        final JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.ES512), new Payload("x"));
        jws.sign(h521.signer());
        assertThat(jws.verify(new ECDSAVerifier((ECPublicKey) p521.leaf.getPublicKey()))).isTrue();
    }

    @Test
    void signer_refusesAnotherAlgorithm_andDoesNotExposeThePrivateKey() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        final SigningKeyHandle handle = keys.resolve(realm,
                keys.importKey(realm, "k", pem(pki.leafKey.getPrivate()), pem(pki.leaf)));

        final JWSObject es384 = new JWSObject(new JWSHeader(JWSAlgorithm.ES384), new Payload("x"));
        assertThatThrownBy(() -> es384.sign(handle.signer())).isInstanceOf(com.nimbusds.jose.JOSEException.class);
        // Not a Nimbus ECDSASigner (which has a public getPrivateKey()).
        assertThat(handle.signer()).isNotInstanceOf(com.nimbusds.jose.crypto.ECDSASigner.class);
        assertThat(handle.toString()).doesNotContain("PRIVATE");
    }

    @Test
    void privateKeyColumn_isEncrypted_notPem() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        keys.importKey(realm, "enc", pem(pki.leafKey.getPrivate()), pem(pki.leaf));

        final String stored = jdbc.queryForObject(
                "SELECT private_key FROM verifier_signing_key WHERE realm_id = ? AND name = 'enc'", String.class, realm);
        assertThat(stored).isNotBlank().doesNotContain("PRIVATE KEY").doesNotContain("-----BEGIN");
        assertThat(new AttributeEncryption("0123456789abcdef0123456789abcdef").convertToEntityAttribute(stored))
                .contains("-----BEGIN PRIVATE KEY-----");
        assertThat(jdbc.queryForObject(
                "SELECT alg FROM verifier_signing_key WHERE realm_id = ? AND name = 'enc'", String.class, realm))
                .isEqualTo("ES256");
        assertThat(jdbc.queryForObject("SELECT certificate_chain_pem FROM verifier_signing_key WHERE realm_id = ? "
                + "AND name = 'enc'", String.class, realm)).startsWith("-----BEGIN CERTIFICATE-----");
    }

    @Test
    void sec1EcPrivateKeyPem_isAccepted() throws Exception {
        // BC encodes SEC1 with the named curve, as openssl does (the JDK leaves the parameters out).
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair leafKey = gen.generateKeyPair();
        final KeyPair caKey = ecKeyPair("secp256r1");
        final X509Certificate leaf = cert("CN=CA", caKey, "CN=sec1", leafKey.getPublic(), "SHA256withECDSA", false,
                Instant.now().plus(Duration.ofDays(30)));
        final String sec1 = sec1Pem(leafKey);
        assertThat(sec1).startsWith("-----BEGIN EC PRIVATE KEY-----");
        assertThat(keys.resolve(realm, keys.importKey(realm, "sec1", sec1, pem(leaf))).algorithm())
                .isEqualTo(JWSAlgorithm.ES256);
    }

    // ---------------------------------------------------------------- import refusals

    @Test
    void keyCertificateMismatch_isRefused() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        final KeyPair other = ecKeyPair("secp256r1");
        assertThatThrownBy(() -> keys.importKey(realm, "mismatch", pem(other.getPrivate()), pem(pki.leaf)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("private key does not match the certificate");
        assertThat(rows("mismatch")).isZero();
    }

    @Test
    void rsaKeys_areRefused_1024_and_2048() throws Exception {
        for (final int bits : new int[] {1024, 2048}) {
            final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(bits);
            final KeyPair caKey = gen.generateKeyPair();
            final KeyPair leafKey = gen.generateKeyPair();
            final X509Certificate ca = cert("CN=RSA CA", caKey, "CN=RSA CA", caKey.getPublic(), "SHA256withRSA",
                    true, Instant.now().plus(Duration.ofDays(30)));
            final X509Certificate leaf = cert("CN=RSA CA", caKey, "CN=rsa leaf", leafKey.getPublic(), "SHA256withRSA",
                    false, Instant.now().plus(Duration.ofDays(30)));
            assertThatThrownBy(() -> keys.importKey(realm, "rsa" + bits, pem(leafKey.getPrivate()), pem(leaf) + pem(ca)))
                    .as("RSA %d", bits)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("RSA keys are not supported");
        }
    }

    @Test
    void selfSignedLeaf_isRefused_haip() throws Exception {
        final KeyPair kp = ecKeyPair("secp256r1");
        final X509Certificate selfSigned = cert("CN=self", kp, "CN=self", kp.getPublic(), "SHA256withECDSA", false,
                Instant.now().plus(Duration.ofDays(30)));
        assertThatThrownBy(() -> keys.importKey(realm, "self", pem(kp.getPrivate()), pem(selfSigned)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must not be self-signed");
    }

    @Test
    void expiredLeaf_isRefused() throws Exception {
        final KeyPair caKey = ecKeyPair("secp256r1");
        final KeyPair leafKey = ecKeyPair("secp256r1");
        final X509Certificate expired = cert("CN=CA", caKey, "CN=old", leafKey.getPublic(), "SHA256withECDSA", false,
                Instant.now().minus(Duration.ofDays(1)));
        assertThatThrownBy(() -> keys.importKey(realm, "old", pem(leafKey.getPrivate()), pem(expired)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void chainNotLeafFirst_isRefused() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        // intermediate before leaf: the first certificate's key is not the private key's...
        assertThatThrownBy(() -> keys.importKey(realm, "order", pem(pki.leafKey.getPrivate()),
                pem(pki.intermediate) + pem(pki.leaf)))
                .isInstanceOf(IllegalArgumentException.class);
        // ...and a leaf followed by a certificate that did not issue it is not a chain.
        final Pki unrelated = Pki.ec("secp256r1", "SHA256withECDSA");
        assertThatThrownBy(() -> keys.importKey(realm, "order2", pem(pki.leafKey.getPrivate()),
                pem(pki.leaf) + pem(unrelated.intermediate)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("leaf first");
    }

    @Test
    void invalidInput_isRefused() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        final String key = pem(pki.leafKey.getPrivate());
        final String chain = pem(pki.leaf);
        assertThatThrownBy(() -> keys.importKey(realm, "bad/name", key, chain))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("name");
        assertThatThrownBy(() -> keys.importKey(realm, "x".repeat(65), key, chain))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("name");
        assertThatThrownBy(() -> keys.importKey(realm, "nokey", "not a pem", chain))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("private key");
        assertThatThrownBy(() -> keys.importKey(realm, "nochain", key, ""))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("certificate");
        assertThatThrownBy(() -> keys.importKey("", "k", key, chain))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("realm");
    }

    @Test
    void duplicateName_isRefused() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        keys.importKey(realm, "dup", pem(pki.leafKey.getPrivate()), pem(pki.leaf));
        assertThatThrownBy(() -> keys.importKey(realm, "dup", pem(pki.leafKey.getPrivate()), pem(pki.leaf)))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("already exists");
    }

    // ---------------------------------------------------------------- resolve refusals

    @Test
    void pkcs11AndKmsRefs_areNotSupportedYet() {
        assertThatThrownBy(() -> keys.resolve(realm, "pkcs11:token=helix;object=eudi"))
                .isInstanceOf(UnsupportedOperationException.class).hasMessageContaining("not supported yet");
        assertThatThrownBy(() -> keys.resolve(realm, "kms:arn:aws:kms:eu-west-1:1:key/abc"))
                .isInstanceOf(UnsupportedOperationException.class).hasMessageContaining("not supported yet");
        assertThatThrownBy(() -> keys.resolve(realm, "file:/etc/key.pem"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("key reference");
    }

    @Test
    void anotherRealmsKey_isNotFound() throws Exception {
        final Pki pki = Pki.ec("secp256r1", "SHA256withECDSA");
        final String ref = keys.importKey(realm, "mine", pem(pki.leafKey.getPrivate()), pem(pki.leaf));
        final String other = E2eSeed.unique("vkeys-other");

        assertThatThrownBy(() -> keys.resolve(other, ref))
                .isInstanceOf(NoSuchElementException.class).hasMessageContaining("not found");
        // Same name in the other realm does not exist either.
        assertThatThrownBy(() -> keys.resolve(other, "software:" + other + "/mine"))
                .isInstanceOf(NoSuchElementException.class).hasMessageContaining("not found");
        assertThatThrownBy(() -> keys.resolve(realm, "software:" + realm + "/missing"))
                .isInstanceOf(NoSuchElementException.class).hasMessageContaining("not found");
    }

    // ---------------------------------------------------------------- helpers

    private int rows(final String name) {
        final Integer n = jdbc.queryForObject("SELECT count(*) FROM verifier_signing_key WHERE realm_id = ? AND name = ?",
                Integer.class, realm, name);
        return n == null ? 0 : n;
    }

    /** A CA (self-signed, trust anchor) → intermediate → leaf; and a leaf issued directly by the CA ({@code leaf}). */
    private record Pki(KeyPair caKey, X509Certificate ca, KeyPair intermediateKey, X509Certificate intermediate,
                       KeyPair leafKey, X509Certificate leaf) {
        static Pki ec(final String curve, final String sigAlg) throws Exception {
            final Instant until = Instant.now().plus(Duration.ofDays(30));
            final KeyPair caKey = ecKeyPair(curve);
            final X509Certificate ca = cert("CN=Test Root", caKey, "CN=Test Root", caKey.getPublic(), sigAlg, true, until);
            final KeyPair intKey = ecKeyPair(curve);
            final X509Certificate intermediate = cert("CN=Test Root", caKey, "CN=Test Intermediate", intKey.getPublic(),
                    sigAlg, true, until);
            final KeyPair leafKey = ecKeyPair(curve);
            // The ES512 test uses leaf+intermediate, the others leaf+root: issue the P-521 leaf from the intermediate.
            final boolean viaIntermediate = "secp521r1".equals(curve);
            final X509Certificate leaf = viaIntermediate
                    ? cert("CN=Test Intermediate", intKey, "CN=verifier.example", leafKey.getPublic(), sigAlg, false, until)
                    : cert("CN=Test Root", caKey, "CN=verifier.example", leafKey.getPublic(), sigAlg, false, until);
            return new Pki(caKey, ca, intKey, intermediate, leafKey, leaf);
        }
    }

    private static KeyPair ecKeyPair(final String curve) throws Exception {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec(curve));
        return gen.generateKeyPair();
    }

    private static X509Certificate cert(final String issuer, final KeyPair issuerKey, final String subject,
                                        final PublicKey subjectKey, final String sigAlg, final boolean ca,
                                        final Instant notAfter) throws Exception {
        final Instant notBefore = notAfter.isBefore(Instant.now())
                ? notAfter.minus(Duration.ofDays(30)) : Instant.now().minus(Duration.ofMinutes(5));
        final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(notBefore), Date.from(notAfter),
                new X500Name(subject), subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        final PrivateKey signingKey = issuerKey.getPrivate();
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder(sigAlg).build(signingKey)));
    }

    private static String pem(final Object o) throws Exception {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            w.writeObject(o instanceof PrivateKey k ? new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(k, null) : o);
        }
        return out.toString();
    }

    /** {@code -----BEGIN EC PRIVATE KEY-----} (SEC1), as {@code openssl ecparam -genkey} writes it. */
    private static String sec1Pem(final KeyPair kp) throws Exception {
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            w.writeObject(kp);
        }
        return out.toString();
    }
}
