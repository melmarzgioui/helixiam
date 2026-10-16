/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.service.key;

import com.nimbusds.jose.jwk.ECKey;
import io.helixiam.testsupport.TestPki;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RealmKeyMaterialTest {

    private static final TestPki.Ca CA = TestPki.ca("Test Root CA");

    // ------------------------------------------------------------------ private keys

    @Test
    void parsesRsaPkcs8_andPkcs1() {
        final KeyPair kp = TestPki.rsa(2048);
        final RealmKeyMaterial.Parsed pkcs8 = RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(kp.getPrivate()));
        final RealmKeyMaterial.Parsed pkcs1 = RealmKeyMaterial.parsePrivateKey(TestPki.traditional(kp));
        assertThat(TestPki.traditional(kp)).contains("BEGIN RSA PRIVATE KEY");
        assertThat(pkcs8.algorithm()).isEqualTo("RS256");
        assertThat(pkcs1.algorithm()).isEqualTo("RS256");
        assertThat(pkcs8.keyPair().getPublic()).isEqualTo(kp.getPublic());
        assertThat(pkcs1.keyPair().getPublic()).isEqualTo(kp.getPublic());
    }

    @Test
    void parsesEcP256_pkcs8_andSec1() {
        final KeyPair kp = TestPki.ec("secp256r1");
        assertThat(RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(kp.getPrivate())).algorithm()).isEqualTo("ES256");
        final RealmKeyMaterial.Parsed sec1 = RealmKeyMaterial.parsePrivateKey(TestPki.traditional(kp));
        assertThat(sec1.algorithm()).isEqualTo("ES256");
        assertThat(sec1.keyPair().getPublic().getEncoded()).isEqualTo(kp.getPublic().getEncoded());
    }

    @Test
    void refusesWeakRsa() {
        final String pem = TestPki.pkcs8(TestPki.rsa(1024).getPrivate());
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(pem))
                .isInstanceOf(KeyImportException.class)
                .hasMessageContaining("at least 2048")
                .satisfies(e -> assertThat(((KeyImportException) e).field()).isEqualTo("privateKeyPem"));
    }

    @Test
    void refusesUnsupportedCurves() {
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(TestPki.ec("secp384r1").getPrivate())))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("P-256");
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(TestPki.ecBc("secp256k1").getPrivate())))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("Unsupported EC curve");
    }

    @Test
    void refusesGarbage_encrypted_andCertificatesAsKeys_withoutEchoingInput() throws Exception {
        final String garbage = "-----BEGIN PRIVATE KEY-----\nU0VDUkVUU0VDUkVU\n-----END PRIVATE KEY-----\n";
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(garbage))
                .isInstanceOf(KeyImportException.class)
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("U0VDUkVU"));
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(" "))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("required");

        final KeyPair kp = TestPki.rsa(2048);
        final OutputEncryptor enc = new JceOpenSSLPKCS8EncryptorBuilder(JcaPKCS8Generator.AES_256_CBC)
                .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
                .setPassword("pw".toCharArray()).build();
        final StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
            w.writeObject(new JcaPKCS8Generator(kp.getPrivate(), enc));
        }
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(out.toString()))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("encrypted");

        final String cert = TestPki.pem(TestPki.selfSigned(kp, "CN=x", 10));
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(cert)).isInstanceOf(KeyImportException.class);
    }

    // ------------------------------------------------------------------ chains

    @Test
    void acceptsCaIssuedChain_andSingleSelfSigned() {
        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate leaf = TestPki.issue(CA, "CN=idp.example", kp.getPublic(), 90);
        final List<X509Certificate> chain = RealmKeyMaterial.parseChain(TestPki.pem(leaf, CA.certificate()));
        RealmKeyMaterial.validateChain(chain, kp.getPublic(), Instant.now());
        assertThat(RealmKeyMaterial.x5cChain(chain)).containsExactly(leaf);

        final TestPki.Ca inter = TestPki.intermediate(CA, "Issuing CA");
        final X509Certificate leaf2 = TestPki.issue(inter, "CN=idp2.example", kp.getPublic(), 90);
        final List<X509Certificate> three = List.of(leaf2, inter.certificate(), CA.certificate());
        RealmKeyMaterial.validateChain(three, kp.getPublic(), Instant.now());
        assertThat(RealmKeyMaterial.x5cChain(three)).containsExactly(leaf2, inter.certificate());

        final X509Certificate self = TestPki.selfSigned(kp, "CN=self", 30);
        RealmKeyMaterial.validateChain(List.of(self), kp.getPublic(), Instant.now());
        assertThat(RealmKeyMaterial.x5cChain(List.of(self))).containsExactly(self);
    }

    @Test
    void refusesMismatchedKey() {
        final X509Certificate leaf = TestPki.issue(CA, "CN=other", TestPki.rsa(2048).getPublic(), 90);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(leaf), TestPki.rsa(2048).getPublic(),
                Instant.now()))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("does not match")
                .satisfies(e -> assertThat(((KeyImportException) e).field()).isEqualTo("certificateChainPem"));
    }

    @Test
    void refusesExpired_notYetValid_andExpiredIntermediate() {
        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate expired = TestPki.issue(CA.certificate(), CA.keyPair().getPrivate(), "CN=old",
                kp.getPublic(), Instant.now().minus(Duration.ofDays(40)), Instant.now().minus(Duration.ofDays(1)),
                KeyUsage.digitalSignature);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(expired, CA.certificate()), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class).hasMessageContaining("expired");

        final X509Certificate future = TestPki.issue(CA.certificate(), CA.keyPair().getPrivate(), "CN=new",
                kp.getPublic(), Instant.now().plus(Duration.ofDays(2)), Instant.now().plus(Duration.ofDays(40)),
                KeyUsage.digitalSignature);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(future), kp.getPublic(), Instant.now()))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("not yet valid");

        final KeyPair interKp = TestPki.rsa(2048);
        final X509Certificate oldInter = TestPki.issue(CA.certificate(), CA.keyPair().getPrivate(), "CN=Old Issuing",
                interKp.getPublic(), Instant.now().minus(Duration.ofDays(40)), Instant.now().minus(Duration.ofDays(1)),
                KeyUsage.keyCertSign);
        final X509Certificate leaf = TestPki.issue(oldInter, interKp.getPrivate(), "CN=leaf", kp.getPublic(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(30)),
                KeyUsage.digitalSignature);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(leaf, oldInter), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class).hasMessageContaining("certificate 2");
    }

    @Test
    void refusesWrongChainOrder_andUnrelatedIssuer() {
        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate leaf = TestPki.issue(CA, "CN=idp", kp.getPublic(), 90);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(CA.certificate(), leaf), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class);
        final TestPki.Ca other = TestPki.ca("Other CA");
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(leaf, other.certificate()), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class).hasMessageContaining("leaf first");
    }

    @Test
    void refusesLeafWithoutDigitalSignature_butAcceptsNoKeyUsage() {
        final KeyPair kp = TestPki.rsa(2048);
        final Instant nb = Instant.now().minus(Duration.ofDays(1));
        final Instant na = Instant.now().plus(Duration.ofDays(30));
        final X509Certificate encOnly = TestPki.issue(CA.certificate(), CA.keyPair().getPrivate(), "CN=enc",
                kp.getPublic(), nb, na, KeyUsage.keyEncipherment);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(encOnly), kp.getPublic(), Instant.now()))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("digitalSignature");
        final X509Certificate none = TestPki.issue(CA.certificate(), CA.keyPair().getPrivate(), "CN=none",
                kp.getPublic(), nb, na, -1);
        RealmKeyMaterial.validateChain(List.of(none), kp.getPublic(), Instant.now());
    }

    @Test
    void refusesNonCertificatePem() {
        assertThatThrownBy(() -> RealmKeyMaterial.parseChain(TestPki.pkcs8(TestPki.rsa(2048).getPrivate())))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("only PEM certificates");
        assertThatThrownBy(() -> RealmKeyMaterial.parseChain("")).isInstanceOf(KeyImportException.class);
    }

    // ------------------------------------------------------------------ CSR, kid, fingerprints

    @Test
    void csr_carriesSubjectSansAndThePublicKey_signedByTheKey() throws Exception {
        for (final String alg : List.of("RS256", "ES256")) {
            final KeyPair kp = RealmKeyMaterial.generate(alg);
            final String pem = RealmKeyMaterial.csr(kp, alg, "CN=idp.example.com, O=Example, C=NL",
                    List.of("idp.example.com"));
            assertThat(pem).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
            try (PEMParser p = new PEMParser(new StringReader(pem))) {
                final PKCS10CertificationRequest csr = (PKCS10CertificationRequest) p.readObject();
                assertThat(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(
                        csr.getSubjectPublicKeyInfo()))).isTrue();
                assertThat(new JcaPKCS10CertificationRequest(csr).getPublicKey().getEncoded())
                        .isEqualTo(kp.getPublic().getEncoded());
                assertThat(csr.getSubject().toString()).contains("CN=idp.example.com");
                assertThat(csr.getAttributes()).isNotEmpty();
            }
            final X509Certificate signed = TestPki.signCsr(CA, pem, 90);
            RealmKeyMaterial.validateChain(List.of(signed, CA.certificate()), kp.getPublic(), Instant.now());
        }
        assertThat(RealmKeyMaterial.generate("ES256").getPublic()).isInstanceOf(ECPublicKey.class);
        assertThat(((RSAPublicKey) RealmKeyMaterial.generate("RS256").getPublic()).getModulus().bitLength())
                .isEqualTo(2048);
    }

    @Test
    void csr_refusesBadSubject_andDnsNames() {
        final KeyPair kp = RealmKeyMaterial.generate("RS256");
        assertThatThrownBy(() -> RealmKeyMaterial.csr(kp, "RS256", "not a dn", List.of()))
                .isInstanceOf(KeyImportException.class)
                .satisfies(e -> assertThat(((KeyImportException) e).field()).isEqualTo("subject"));
        assertThatThrownBy(() -> RealmKeyMaterial.csr(kp, "RS256", "CN=ok", List.of("bad name!")))
                .isInstanceOf(KeyImportException.class)
                .satisfies(e -> assertThat(((KeyImportException) e).field()).isEqualTo("dnsNames"));
        assertThatThrownBy(() -> RealmKeyMaterial.generate("HS256"))
                .isInstanceOf(KeyImportException.class)
                .satisfies(e -> assertThat(((KeyImportException) e).field()).isEqualTo("algorithm"));
    }

    @Test
    void kid_rsaKeepsTheLegacyModulusDerivation_ecUsesTheThumbprint() throws Exception {
        final KeyPair rsa = TestPki.rsa(2048);
        final String legacy = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                .digest(((RSAPublicKey) rsa.getPublic()).getModulus().toByteArray()));
        assertThat(RealmKeyMaterial.kid(rsa.getPublic())).isEqualTo(legacy);
        final KeyPair ec = TestPki.ec("secp256r1");
        assertThat(RealmKeyMaterial.kid(ec.getPublic())).isEqualTo(
                new ECKey.Builder(com.nimbusds.jose.jwk.Curve.P_256, (ECPublicKey) ec.getPublic()).build()
                        .computeThumbprint().toString());
    }

    @Test
    void algorithmNormalisation_andDecodeRoundTrip() {
        assertThat(RealmKeyMaterial.normalizeAlgorithm("RSA")).isEqualTo("RS256");
        assertThat(RealmKeyMaterial.normalizeAlgorithm(null)).isEqualTo("RS256");
        assertThat(RealmKeyMaterial.normalizeAlgorithm("ES256")).isEqualTo("ES256");
        for (final String alg : List.of("RS256", "ES256", "RSA")) {
            final KeyPair kp = RealmKeyMaterial.generate(RealmKeyMaterial.normalizeAlgorithm(alg));
            final KeyPair back = RealmKeyMaterial.decode(alg,
                    Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()),
                    Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
            assertThat(back.getPublic()).isEqualTo(kp.getPublic());
            assertThat(back.getPrivate()).isEqualTo(kp.getPrivate());
        }
    }

    @Test
    void fingerprint_isColonHexSha256_andSelfSignedIsDeterministic() throws Exception {
        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate self = TestPki.selfSigned(kp, "CN=fp", 3);
        assertThat(RealmKeyMaterial.fingerprint(self)).matches("([0-9A-F]{2}:){31}[0-9A-F]{2}");
        for (final KeyPair k : List.of(kp, TestPki.ec("secp256r1"))) {
            final X509Certificate a = RealmKeyMaterial.selfSigned("acme", k);
            final X509Certificate b = RealmKeyMaterial.selfSigned("acme", k);
            assertThat(a.getEncoded()).isEqualTo(b.getEncoded());
            a.verify(k.getPublic());
            assertThat(a.getSubjectX500Principal().getName()).isEqualTo("CN=helix-idp-acme");
        }
    }

    @Test
    void chainPem_roundTrips() {
        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate leaf = TestPki.issue(CA, "CN=rt", kp.getPublic(), 10);
        final String pem = RealmKeyMaterial.chainToPem(List.of(leaf, CA.certificate()));
        assertThat(RealmKeyMaterial.parseChain(pem)).containsExactly(leaf, CA.certificate());
    }

    // ------------------------------------------------------------------ review round 1

    @Test
    void refusesACaLeaf_andNonCaIssuers() {
        final KeyPair kp = TestPki.rsa(2048);
        final X509Certificate caLeaf = TestPki.issueCaLeaf(CA, "CN=ca-leaf", kp.getPublic());
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(caLeaf, CA.certificate()), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class).hasMessageContaining("CA");

        final TestPki.Ca notCa = TestPki.nonCaIssuer(CA, "Not A CA", KeyUsage.digitalSignature | KeyUsage.keyCertSign);
        final X509Certificate leaf = TestPki.issue(notCa, "CN=leaf", kp.getPublic(), 30);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(leaf, notCa.certificate()), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class).hasMessageContaining("certificate 2");

        final TestPki.Ca noSign = TestPki.caWithoutKeyCertSign("No KeyCertSign");
        final X509Certificate leaf2 = TestPki.issue(noSign, "CN=leaf2", kp.getPublic(), 30);
        assertThatThrownBy(() -> RealmKeyMaterial.validateChain(List.of(leaf2, noSign.certificate()), kp.getPublic(),
                Instant.now())).isInstanceOf(KeyImportException.class).hasMessageContaining("keyCertSign");
    }

    @Test
    void refusesKeyPemWithASecondObjectOrTrailingData() {
        final KeyPair kp = TestPki.rsa(2048);
        final String pem = TestPki.pkcs8(kp.getPrivate());
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(pem + TestPki.pkcs8(TestPki.rsa(2048).getPrivate())))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("exactly one");
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(pem + TestPki.pem(TestPki.selfSigned(kp, "CN=x", 3))))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("exactly one");
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(pem + "trailing junk"))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("exactly one");
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey("junk before\n" + pem))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("exactly one");
        assertThat(RealmKeyMaterial.parsePrivateKey("\n  " + pem + "\n\n").algorithm()).isEqualTo("RS256");
    }

    @Test
    void rsa_requiresExponent65537OrMore_andAtMost4096Bits() {
        final KeyPair e3 = TestPki.rsa(2048, java.math.BigInteger.valueOf(3));
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(e3.getPrivate())))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("65537");
        final KeyPair big = TestPki.rsa(4096 + 1024);
        assertThatThrownBy(() -> RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(big.getPrivate())))
                .isInstanceOf(KeyImportException.class).hasMessageContaining("4096");
        assertThat(RealmKeyMaterial.parsePrivateKey(TestPki.pkcs8(TestPki.rsa(4096).getPrivate())).algorithm())
                .isEqualTo("RS256");
    }

    @Test
    void subject_allowsKnownKeywordsOnly_noOidsOrHexValues() {
        RealmKeyMaterial.parseSubject("CN=idp.example.com, O=Example, OU=IAM, C=NL, L=Arnhem, ST=Gelderland, "
                + "emailAddress=ops@example.com, SERIALNUMBER=123, DC=example, UID=svc");
        RealmKeyMaterial.parseSubject("CN=a\\, b, O=Example");
        for (final String bad : List.of("2.5.4.3=idp", "CN=#04024869", "XYZ=1", "CN=a+2.5.4.10=b", "CN=ok, OID.2.5.4.3=x")) {
            assertThatThrownBy(() -> RealmKeyMaterial.parseSubject(bad)).as(bad)
                    .isInstanceOf(KeyImportException.class)
                    .satisfies(e -> assertThat(((KeyImportException) e).field()).isEqualTo("subject"));
        }
    }
}
