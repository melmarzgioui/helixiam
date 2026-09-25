/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * SAML-7: the HTTP-Redirect {@code SigAlg} must be a strong RSA-SHA (256/384/512). {@code rsa-sha1}
 * and any unknown algorithm are rejected — even when the signature is cryptographically valid — rather
 * than silently verified as SHA-256.
 */
class SamlAuthnRequestParserSigAlgTest {

    private static final String SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private static final String UNKNOWN = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";

    private final SamlAuthnRequestParser parser = new SamlAuthnRequestParser();
    private static KeyPair kp;
    private static String certPem;

    @BeforeAll
    static void keys() throws Exception {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        kp = kpg.generateKeyPair();
        certPem = pem(selfSigned(kp));
    }

    @Test
    void acceptsAValidSha256Signature() throws Exception {
        assertThat(parser.isRedirectSignatureValid(signedQuery(SHA256, "SHA256withRSA"), certPem)).isTrue();
    }

    @Test
    void rejectsRsaSha1EvenWhenTheSignatureIsValid() throws Exception {
        // A correctly-computed SHA-1 signature must still be refused.
        assertThat(parser.isRedirectSignatureValid(signedQuery(SHA1, "SHA1withRSA"), certPem)).isFalse();
    }

    @Test
    void rejectsAnUnknownSigAlg() throws Exception {
        assertThat(parser.isRedirectSignatureValid(signedQuery(UNKNOWN, "SHA256withRSA"), certPem)).isFalse();
    }

    /** Build a SAML HTTP-Redirect query signed over the {@code SAMLRequest=..&SigAlg=..} octet string. */
    private static String signedQuery(final String sigAlgUri, final String jcaSignAlg) throws Exception {
        final String samlRequestRaw = URLEncoder.encode("PHNhbWxwOkF1dGhuUmVxdWVzdC8+", UTF_8);
        final String sigAlgRaw = URLEncoder.encode(sigAlgUri, UTF_8);
        final String octet = "SAMLRequest=" + samlRequestRaw + "&SigAlg=" + sigAlgRaw;
        final Signature s = Signature.getInstance(jcaSignAlg);
        s.initSign(kp.getPrivate());
        s.update(octet.getBytes(UTF_8));
        final String signatureRaw = URLEncoder.encode(Base64.getEncoder().encodeToString(s.sign()), UTF_8);
        return octet + "&Signature=" + signatureRaw;
    }

    private static X509Certificate selfSigned(final KeyPair kp) throws Exception {
        final long now = System.currentTimeMillis();
        final org.bouncycastle.asn1.x500.X500Name name = new org.bouncycastle.asn1.x500.X500Name("CN=SP");
        final JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now - 60_000), new Date(now + 86_400_000L),
                name, kp.getPublic());
        final ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        final X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private static String pem(final X509Certificate cert) throws Exception {
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
    }
}
