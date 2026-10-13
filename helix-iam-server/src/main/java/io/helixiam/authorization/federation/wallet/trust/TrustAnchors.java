/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.IOException;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The issuer trust configuration of one wallet provider: the anchors credential issuers must chain to, optional
 * pinned intermediates (used to complete an {@code x5c} / {@code x5chain} that omits them), and how certificate
 * revocation is checked. Validation is done by {@link IssuerTrustValidator}.
 */
public record TrustAnchors(Set<TrustAnchor> anchors, List<X509Certificate> pinnedIntermediates,
        RevocationMode revocation) {

    /** How issuer-certificate revocation (CRL/OCSP) is handled. */
    public enum RevocationMode { OFF, SOFT_FAIL, HARD_FAIL }

    /** Index of {@code keyCertSign} in {@link X509Certificate#getKeyUsage()}. */
    private static final int KEY_CERT_SIGN = 5;

    /** A null {@code revocation} means {@link RevocationMode#HARD_FAIL} (the default; see docs/eudi-wallet.md). */
    public TrustAnchors {
        revocation = revocation == null ? RevocationMode.HARD_FAIL : revocation;
        anchors = anchors == null ? Set.of() : Set.copyOf(anchors);
        pinnedIntermediates = pinnedIntermediates == null ? List.of() : List.copyOf(pinnedIntermediates);
    }

    /**
     * Loads the anchors from a PEM bundle (one or more {@code CERTIFICATE} blocks) and the optional pinned
     * intermediates from a second bundle ({@code null} or blank for none).
     *
     * <p>Every anchor must be a CA certificate (spec §7.5 "PEM CA certificates"): basicConstraints {@code cA=true}, a
     * key usage (when present) that includes {@code keyCertSign}, and a key that meets the issuer key rule (EC
     * P-256/P-384/P-521 or RSA &ge; 2048). A null {@code mode} means {@code SOFT_FAIL}.
     *
     * @throws IllegalArgumentException when the bundle holds no certificate, a block is not a certificate or cannot be
     *                                  parsed, or an anchor is not an acceptable CA certificate. The message is
     *                                  field-safe: never PEM content or parser detail.
     */
    public static TrustAnchors fromPem(final String pemBundle, final String intermediatesPem,
            final RevocationMode mode) {
        final List<X509Certificate> roots = parse(pemBundle == null ? "" : pemBundle, "trust anchors");
        if (roots.isEmpty()) {
            throw new IllegalArgumentException("The trust anchors must contain at least one PEM certificate");
        }
        final Set<TrustAnchor> anchors = new LinkedHashSet<>();
        for (final X509Certificate root : roots) {
            requireCaAnchor(root);
            anchors.add(new TrustAnchor(root, null));
        }
        final List<X509Certificate> intermediates = intermediatesPem == null || intermediatesPem.isBlank()
                ? List.of() : parse(intermediatesPem, "pinned intermediates");
        return new TrustAnchors(anchors, intermediates, mode);
    }

    private static void requireCaAnchor(final X509Certificate cert) {
        final String problem = trustAnchorProblem(cert);
        if (problem != null) {
            throw new IllegalArgumentException(problem);
        }
    }

    /**
     * Why {@code cert} cannot be a trust anchor ({@link #fromPem}'s rule: a CA certificate whose key usage, if any,
     * allows certificate signing, with an allowed key), or {@code null} when it can. The admin console's certificate
     * preview shows it per certificate.
     */
    public static String trustAnchorProblem(final X509Certificate cert) {
        if (cert.getBasicConstraints() < 0) {
            return "A trust anchor is not a CA certificate";
        }
        final boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null && (keyUsage.length <= KEY_CERT_SIGN || !keyUsage[KEY_CERT_SIGN])) {
            return "A trust anchor's key usage does not allow certificate signing";
        }
        if (!IssuerTrustValidator.allowedKey(cert.getPublicKey())) {
            return "A trust anchor's key type or size is not allowed (EC P-256/P-384/P-521 or RSA >= 2048)";
        }
        return null;
    }

    private static List<X509Certificate> parse(final String pem, final String what) {
        final List<X509Certificate> certs = new ArrayList<>();
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        boolean foreign = false;
        try (PEMParser parser = new PEMParser(new StringReader(pem))) {
            Object o;
            while ((o = parser.readObject()) != null) {
                if (!(o instanceof X509CertificateHolder holder)) {
                    foreign = true;
                    break;
                }
                certs.add(converter.getCertificate(holder));
            }
        } catch (final IOException | GeneralSecurityException | RuntimeException e) {
            // BouncyCastle reports malformed base64 / ASN.1 with runtime exceptions; never surface its message.
            throw new IllegalArgumentException("The " + what + " could not be parsed as PEM certificates");
        }
        if (foreign) {
            throw new IllegalArgumentException("The " + what + " must contain only PEM certificates");
        }
        return certs;
    }
}
