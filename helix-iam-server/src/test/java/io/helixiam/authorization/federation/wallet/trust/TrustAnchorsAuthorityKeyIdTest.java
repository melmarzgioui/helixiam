/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.LeafSpec;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * HAIP §5 / OpenID4VP §6.1.1.1: the {@code aki} Trusted Authorities Query lists the key identifiers that the
 * AuthorityKeyIdentifier of a certificate in the credential's chain carries. A certificate an anchor issued names the
 * anchor's key identifier, so the values are the anchors' (and pinned intermediates') own key identifiers.
 */
class TrustAnchorsAuthorityKeyIdTest {

    private static final TestPki PKI = TestPki.create();
    private static final TestPki OTHER = TestPki.create("Other");

    @Test
    void authorityKeyIdentifiers_areWhatCertificatesIssuedByTheAnchorsCarryAsTheirAki() throws Exception {
        final TrustAnchors anchors = TrustAnchors.fromPem(PKI.rootPem() + OTHER.rootPem(), PKI.intermediatePem(),
                RevocationMode.OFF);
        final X509Certificate leaf = PKI.issueLeaf(LeafSpec.defaults()).certificate();

        assertThat(anchors.authorityKeyIdentifiers()).containsExactlyInAnyOrder(
                aki(PKI.intermediate()),   // the PKI root, which issued the intermediate
                aki(OTHER.intermediate()), // the other root
                aki(leaf));                // the pinned intermediate, which issued the leaf
    }

    @Test
    void authorityKeyIdentifiers_areUnpaddedBase64Url_sorted_andWithoutDuplicates() {
        final TrustAnchors anchors = TrustAnchors.fromPem(PKI.rootPem() + OTHER.rootPem() + PKI.rootPem(), null,
                RevocationMode.OFF);

        assertThat(anchors.authorityKeyIdentifiers()).hasSize(2).isSorted()
                .allSatisfy(v -> assertThat(v).matches("[A-Za-z0-9_-]+"));
    }

    /** An anchor without a SubjectKeyIdentifier: RFC 5280 §4.2.1.2 method (1), SHA-1 of the subjectPublicKey. */
    @Test
    void anAnchorWithoutASubjectKeyIdentifier_usesTheRfc5280Method1KeyId() throws Exception {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        final KeyPair keys = generator.generateKeyPair();
        final X500Name name = new X500Name("CN=No SKI root");
        final X509Certificate root = new JcaX509CertificateConverter().getCertificate(new X509v3CertificateBuilder(
                name, BigInteger.ONE, Date.from(Instant.now().minusSeconds(60)),
                Date.from(Instant.now().plusSeconds(3600)), name,
                SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()))
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
        assertThat(root.getExtensionValue(Extension.subjectKeyIdentifier.getId())).isNull();
        final byte[] keyBits = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()).getPublicKeyData()
                .getBytes();
        final String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-1").digest(keyBits));

        final TrustAnchors anchors = new TrustAnchors(Set.of(new TrustAnchor(root, null)), null, RevocationMode.OFF);

        assertThat(anchors.authorityKeyIdentifiers()).containsExactly(expected);
    }

    private static String aki(final X509Certificate issued) throws Exception {
        final byte[] keyId = AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(
                issued.getExtensionValue(Extension.authorityKeyIdentifier.getId()))).getKeyIdentifier();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(keyId);
    }
}
