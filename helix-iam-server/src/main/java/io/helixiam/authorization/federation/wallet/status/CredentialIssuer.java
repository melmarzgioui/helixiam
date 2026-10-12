/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Who issued the credential whose status is checked, as the status-list signer rules need it
 * (docs/eudi-wallet-spec-notes.md §6.5, ISO/IEC 18013-5 2nd ed. draft §12.3.6).
 *
 * @param chain                 the credential's issuer certificate chain, leaf first, as presented: the SD-JWT
 *                              {@code x5c} or the mdoc IssuerAuth {@code x5chain}
 * @param statusListCertificate the mdoc MSO {@code status.status_list.certificate} (DER), the trust point for the list
 *                              signer; {@code null} when absent (and always for SD-JWT VC)
 */
public record CredentialIssuer(List<X509Certificate> chain, byte[] statusListCertificate) {

    public CredentialIssuer {
        chain = List.copyOf(Objects.requireNonNull(chain, "chain"));
        statusListCertificate = statusListCertificate == null ? null : statusListCertificate.clone();
    }

    @Override
    public byte[] statusListCertificate() {
        return statusListCertificate == null ? null : statusListCertificate.clone();
    }

    @Override
    public boolean equals(final Object o) {
        return o instanceof CredentialIssuer other && chain.equals(other.chain)
                && Arrays.equals(statusListCertificate, other.statusListCertificate);
    }

    @Override
    public int hashCode() {
        return 31 * chain.hashCode() + Arrays.hashCode(statusListCertificate);
    }

    @Override
    public String toString() {
        return "CredentialIssuer[chain=" + chain.size() + " certificate(s), statusListCertificate="
                + (statusListCertificate == null ? "none" : statusListCertificate.length + " bytes") + "]";
    }
}
