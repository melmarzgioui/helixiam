/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/** Reads a bundle of PEM {@code CERTIFICATE} blocks (a list's pinned signers). */
public final class PemCertificates {

    /** Most signer certificates pinned for one source. */
    public static final int MAX = 16;

    private PemCertificates() {
    }

    /**
     * The certificates of {@code pem}, in order.
     *
     * @throws IllegalArgumentException with a field-safe message (never PEM content) when the bundle is empty, holds
     *                                  anything but certificates, cannot be parsed or holds more than {@link #MAX}
     */
    public static List<X509Certificate> parse(final String pem) {
        final List<X509Certificate> out = new ArrayList<>();
        final JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        try (PEMParser parser = new PEMParser(new StringReader(pem == null ? "" : pem))) {
            Object o;
            while ((o = parser.readObject()) != null) {
                if (!(o instanceof X509CertificateHolder holder)) {
                    throw new IllegalArgumentException("The signer certificates must contain only PEM certificates");
                }
                out.add(converter.getCertificate(holder));
                if (out.size() > MAX) {
                    throw new IllegalArgumentException("At most " + MAX + " signer certificates can be pinned");
                }
            }
        } catch (final IllegalArgumentException e) {
            throw e;
        } catch (final Exception e) {
            throw new IllegalArgumentException("The signer certificates could not be parsed as PEM certificates");
        }
        if (out.isEmpty()) {
            throw new IllegalArgumentException("At least one PEM signer certificate is required");
        }
        return List.copyOf(out);
    }

    /**
     * Why {@code cert} cannot sign a trusted list (its key is too weak or of a type list signatures do not use), or
     * null when it can: RSA of at least 2048 bits, or EC on a curve of at least 256 bits.
     */
    public static String keyProblem(final X509Certificate cert) {
        final java.security.PublicKey key = cert.getPublicKey();
        if (key instanceof java.security.interfaces.RSAPublicKey rsa) {
            return rsa.getModulus().bitLength() >= 2048 ? null
                    : "A signer certificate's RSA key is shorter than 2048 bits";
        }
        if (key instanceof java.security.interfaces.ECPublicKey ec) {
            return ec.getParams().getCurve().getField().getFieldSize() >= 256 ? null
                    : "A signer certificate's EC key is on a curve smaller than P-256";
        }
        return "A signer certificate must have an RSA (at least 2048 bits) or EC (P-256 or stronger) key";
    }
}
