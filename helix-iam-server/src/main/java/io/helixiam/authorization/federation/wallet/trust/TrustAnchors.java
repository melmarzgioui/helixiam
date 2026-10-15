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

    /**
     * The values of the DCQL {@code aki} Trusted Authorities Query (OpenID4VP §6.1.1.1, required by HAIP §5): the
     * SubjectKeyIdentifier of every anchor and pinned intermediate, unpadded base64url, sorted, without duplicates. A
     * certificate one of them issued carries that value as its AuthorityKeyIdentifier, which is what the wallet matches
     * against the chain in the credential. Only a hint for the wallet: the PKIX validation still decides trust.
     *
     * <p><b>Never guessed</b> (security review): when any of them has no SubjectKeyIdentifier
     * ({@link #withoutSubjectKeyIdentifier}), the list is empty and the query carries no {@code trusted_authorities}. A
     * computed key identifier (RFC 5280 method 1) need not be the AKI the issuer actually wrote into the credentials it
     * signed, and a wrong value makes the wallet withhold every credential PKIX would have accepted.
     */
    public List<String> authorityKeyIdentifiers() {
        if (!withoutSubjectKeyIdentifier().isEmpty()) {
            return List.of();
        }
        final java.util.SortedSet<String> out = new java.util.TreeSet<>();
        certificates().forEach(cert -> out.add(java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(subjectKeyIdentifier(cert))));
        return List.copyOf(out);
    }

    /** The anchors and pinned intermediates that carry no SubjectKeyIdentifier extension (see above). */
    public List<X509Certificate> withoutSubjectKeyIdentifier() {
        return certificates().stream().filter(cert -> subjectKeyIdentifier(cert) == null).toList();
    }

    private List<X509Certificate> certificates() {
        final List<X509Certificate> out = new ArrayList<>();
        anchors.forEach(anchor -> out.add(anchor.getTrustedCert()));
        out.addAll(pinnedIntermediates);
        return out;
    }

    /** The SubjectKeyIdentifier's key identifier, or {@code null} without a readable extension. */
    private static byte[] subjectKeyIdentifier(final X509Certificate cert) {
        final byte[] ski = cert.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());
        if (ski == null) {
            return null;
        }
        try {
            return org.bouncycastle.asn1.x509.SubjectKeyIdentifier.getInstance(
                    org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue(ski)).getKeyIdentifier();
        } catch (final java.io.IOException | IllegalArgumentException e) {
            return null; // unreadable: treated like a missing one, never guessed
        }
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
