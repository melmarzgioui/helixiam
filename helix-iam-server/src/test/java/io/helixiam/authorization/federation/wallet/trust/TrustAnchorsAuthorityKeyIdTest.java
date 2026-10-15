/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import io.helixiam.authorization.federation.wallet.testwallet.TestPki;
import io.helixiam.authorization.federation.wallet.testwallet.TestPki.LeafSpec;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors.RevocationMode;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Base64;

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

    /**
     * Security review: never guess a key identifier. An anchor (or pinned intermediate) without a
     * SubjectKeyIdentifier gives no values at all, so the query leaves trusted_authorities out rather than name a
     * value the issued credentials may not carry (the wallet would then offer nothing PKIX would have accepted).
     */
    @Test
    void anAnchorWithoutASubjectKeyIdentifier_givesNoValuesAtAll_andIsNamed() {
        final X509Certificate noSki = TestPki.caCertificate(TestPki.KeyType.EC_P256, null);
        assertThat(noSki.getExtensionValue(Extension.subjectKeyIdentifier.getId())).isNull();

        final TrustAnchors mixed = TrustAnchors.fromPem(PKI.rootPem() + TestPki.pem(noSki), null, RevocationMode.OFF);

        assertThat(mixed.authorityKeyIdentifiers()).isEmpty();
        assertThat(mixed.withoutSubjectKeyIdentifier()).containsExactly(noSki);
        final TrustAnchors pinned = TrustAnchors.fromPem(PKI.rootPem(), TestPki.pem(noSki), RevocationMode.OFF);
        assertThat(pinned.authorityKeyIdentifiers()).isEmpty();
        assertThat(pinned.withoutSubjectKeyIdentifier()).containsExactly(noSki);
    }

    @Test
    void anchorsThatAllHaveASubjectKeyIdentifier_nameNone() {
        assertThat(TrustAnchors.fromPem(PKI.rootPem() + OTHER.rootPem(), PKI.intermediatePem(), RevocationMode.OFF)
                .withoutSubjectKeyIdentifier()).isEmpty();
    }

    private static String aki(final X509Certificate issued) throws Exception {
        final byte[] keyId = AuthorityKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(
                issued.getExtensionValue(Extension.authorityKeyIdentifier.getId()))).getKeyIdentifier();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(keyId);
    }
}
