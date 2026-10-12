/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.controller.admin;

import com.nimbusds.jose.jwk.Curve;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;
import io.helixiam.authorization.service.key.SoftwareRealmSigningKeys;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Task 24: the public facts of one X.509 certificate as the admin console shows them (verifier access keys, the
 * trust-anchor preview). Built only from public certificate fields.
 *
 * @param subject            RFC 2253 subject DN
 * @param issuer             RFC 2253 issuer DN
 * @param serialNumber       hexadecimal
 * @param notBefore          ISO-8601 instant
 * @param notAfter           ISO-8601 instant
 * @param ca                 basicConstraints CA=true
 * @param selfSigned         subject = issuer and the signature verifies with its own key (a root)
 * @param dnsNames           dNSName subjectAltNames (what {@code x509_san_dns} checks)
 * @param keyAlgorithm       e.g. {@code EC P-256}, {@code RSA 2048}
 * @param trustAnchorProblem why it cannot be a wallet trust anchor ({@link TrustAnchors#trustAnchorProblem}), or null
 */
public record CertificateView(String subject, String issuer, String serialNumber, String notBefore, String notAfter,
                              boolean ca, boolean selfSigned, List<String> dnsNames, String keyAlgorithm,
                              String trustAnchorProblem) {

    private static final int DNS_NAME = 2;

    public static CertificateView of(final X509Certificate cert) {
        return new CertificateView(cert.getSubjectX500Principal().getName(X500Principal.RFC2253),
                cert.getIssuerX500Principal().getName(X500Principal.RFC2253), cert.getSerialNumber().toString(16),
                cert.getNotBefore().toInstant().toString(), cert.getNotAfter().toInstant().toString(),
                cert.getBasicConstraints() >= 0, SoftwareRealmSigningKeys.isSelfSigned(cert), dnsNames(cert),
                keyAlgorithm(cert), TrustAnchors.trustAnchorProblem(cert));
    }

    private static List<String> dnsNames(final X509Certificate cert) {
        final List<String> names = new ArrayList<>();
        try {
            final Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (final List<?> san : sans) {
                    if (san.size() >= 2 && Integer.valueOf(DNS_NAME).equals(san.get(0))
                            && san.get(1) instanceof String name) {
                        names.add(name);
                    }
                }
            }
        } catch (final CertificateParsingException e) {
            return List.of();
        }
        return List.copyOf(names);
    }

    private static String keyAlgorithm(final X509Certificate cert) {
        if (cert.getPublicKey() instanceof ECPublicKey ec) {
            final Curve curve = Curve.forECParameterSpec(ec.getParams());
            return curve == null ? "EC" : "EC " + curve.getName();
        }
        if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
            return "RSA " + rsa.getModulus().bitLength();
        }
        return cert.getPublicKey().getAlgorithm();
    }
}
