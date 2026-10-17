/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.idp.saml;

/**
 * Helix IAM E7.1: configuration for Helix acting as a SAML2 <b>Identity Provider</b> — the entity id
 * it asserts under and the key/cert it signs assertions with (sourced from the realm's KMS in prod).
 *
 * @param idpEntityId          Helix's IdP entity id (the assertion Issuer)
 * @param signingCertificate   the IdP signing certificate (PEM), published in IdP metadata
 * @param signingPrivateKey    the IdP signing private key (PEM, PKCS#8; RSA or EC)
 * @param additionalSigningCertificates certificates (PEM) of the realm's PENDING and ROTATED keys, published as extra
 *                             signing KeyDescriptors in metadata so SPs that re-read it can roll over (never sign)
 */
public record SamlIdpConfig(String idpEntityId, String signingCertificate, String signingPrivateKey,
                            java.util.List<String> additionalSigningCertificates) {

    public SamlIdpConfig(final String idpEntityId, final String signingCertificate, final String signingPrivateKey) {
        this(idpEntityId, signingCertificate, signingPrivateKey, java.util.List.of());
    }

    public SamlIdpConfig {
        additionalSigningCertificates = additionalSigningCertificates == null
                ? java.util.List.of() : java.util.List.copyOf(additionalSigningCertificates);
    }

    @Override
    public String toString() {
        return "SamlIdpConfig[" + idpEntityId + "]"; // never the private key
    }
}
