/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.trust.ValidatedChain;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Who issued the credential whose status is checked, as the status-list signer rules need it
 * (docs/eudi-wallet-spec-notes.md §6.5, ISO/IEC 18013-5 2nd ed. draft §12.3.6).
 *
 * @param validated             the credential issuer's chain as PKIX validated it (SD-JWT {@code x5c} / mdoc IssuerAuth
 *                              {@code x5chain}, after trust validation; never the presented chain)
 * @param statusListCertificate the mdoc MSO {@code status.status_list.certificate} (DER), the trust point for the list
 *                              signer; {@code null} when absent (and always for SD-JWT VC)
 */
public record CredentialIssuer(ValidatedChain validated, byte[] statusListCertificate) {

    public CredentialIssuer {
        Objects.requireNonNull(validated, "validated");
        statusListCertificate = statusListCertificate == null ? null : statusListCertificate.clone();
    }

    /** The validated path, leaf first. */
    public List<X509Certificate> chain() {
        return validated.path();
    }

    @Override
    public byte[] statusListCertificate() {
        return statusListCertificate == null ? null : statusListCertificate.clone();
    }

    @Override
    public boolean equals(final Object o) {
        return o instanceof CredentialIssuer other && validated.equals(other.validated)
                && Arrays.equals(statusListCertificate, other.statusListCertificate);
    }

    @Override
    public int hashCode() {
        return 31 * validated.hashCode() + Arrays.hashCode(statusListCertificate);
    }

    @Override
    public String toString() {
        return "CredentialIssuer[path=" + validated.path().size() + " certificate(s), statusListCertificate="
                + (statusListCertificate == null ? "none" : statusListCertificate.length + " bytes") + "]";
    }
}
