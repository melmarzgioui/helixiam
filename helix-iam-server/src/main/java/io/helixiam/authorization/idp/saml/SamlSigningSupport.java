/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

import org.opensaml.xmlsec.signature.support.SignatureConstants;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Shared SAML signing helpers for the IdP's realm key: PEM parsing for RSA <b>and EC</b> keys, and the XML signature
 * algorithm the key can produce (BYO keys D26: an EC key signs {@code ecdsa-sha256} whatever RSA algorithm an SP
 * option names).
 */
final class SamlSigningSupport {

    private SamlSigningSupport() {
    }

    static X509Certificate parseCertificate(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
    }

    /** A PKCS#8 PEM private key, RSA or EC. */
    static PrivateKey parsePrivateKey(final String pem) throws Exception {
        final String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64));
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (final java.security.spec.InvalidKeySpecException e) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    static boolean isEc(final PrivateKey key) {
        return "EC".equalsIgnoreCase(key.getAlgorithm());
    }

    /** {@code rsaAlgorithm} for an RSA key; ECDSA-SHA256 for an EC key. */
    static String signatureAlgorithm(final PrivateKey key, final String rsaAlgorithm) {
        return isEc(key) ? SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA256 : rsaAlgorithm;
    }
}
