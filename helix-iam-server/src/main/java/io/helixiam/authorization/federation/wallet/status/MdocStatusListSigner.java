/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.TrustAnchors;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Who may sign the Token Status List of an mdoc (ISO/IEC 18013-5 2nd ed. draft §12.3.6.2, docs/eudi-wallet-spec-notes.md
 * §6.5). The list is already trusted ({@link StatusListToken} validated its x5chain against the provider's anchors);
 * this binds it to the credential's issuer, so another trusted issuer cannot revoke or vouch for this credential.
 *
 * <ul>
 *   <li><b>With</b> {@code status_list.certificate}: that certificate is the trust point. The list's x5chain must
 *       contain it, or its top certificate must be issued by it. (Stricter than "a trust point" alone: the list must
 *       also chain to the provider's anchors.)</li>
 *   <li><b>Without</b>: the notes' rule is "the list's x5chain top certificate must be signed by the certificate that
 *       signed the MSO x5chain". Accepted: the list chain shares a certificate with the MSO chain (the MSO signer itself,
 *       or the same intermediate, which then has the same issuer); or the list's top is issued by a certificate of the MSO
 *       chain; or the list's top and the MSO chain's top are issued by the same anchor or pinned intermediate (the
 *       IACA). A list under any other CA, however trusted, is refused.</li>
 * </ul>
 * A refusal is {@code STATUS_UNAVAILABLE}: an integrity failure of the list, never subject to {@code onUnavailable}.
 */
final class MdocStatusListSigner {

    private MdocStatusListSigner() {
    }

    /** @throws WalletVerificationException {@code STATUS_UNAVAILABLE} when the list signer is not bound to the issuer */
    static void check(final List<X509Certificate> listChain, final CredentialIssuer issuer,
            final TrustAnchors anchors) {
        if (listChain == null || listChain.isEmpty()) {
            throw refused("Status List Token has no signer chain");
        }
        final X509Certificate listTop = listChain.get(listChain.size() - 1);
        final byte[] certificate = issuer.statusListCertificate();
        if (certificate != null) {
            final X509Certificate point = parse(certificate);
            if (!listChain.contains(point) && !issuedBy(listTop, point)) {
                throw refused("Status List Token signer does not chain to the MSO status_list certificate");
            }
            return;
        }
        final List<X509Certificate> msoChain = issuer.chain();
        if (msoChain.isEmpty()) {
            throw refused("credential issuer chain is empty");
        }
        if (listChain.stream().anyMatch(msoChain::contains)
                || msoChain.stream().anyMatch(m -> issuedBy(listTop, m))) {
            return;
        }
        final X509Certificate msoTop = msoChain.get(msoChain.size() - 1);
        for (final PublicKey caKey : caKeys(anchors)) {
            if (verifies(msoTop, caKey) && verifies(listTop, caKey)) {
                return;
            }
        }
        throw refused("Status List Token is not signed under the credential issuer");
    }

    /** The anchors' and pinned intermediates' public keys: the certificates that can sign the top of a chain. */
    private static List<PublicKey> caKeys(final TrustAnchors anchors) {
        final List<PublicKey> keys = new ArrayList<>();
        for (final TrustAnchor anchor : anchors.anchors()) {
            keys.add(anchor.getTrustedCert() != null ? anchor.getTrustedCert().getPublicKey() : anchor.getCAPublicKey());
        }
        anchors.pinnedIntermediates().forEach(c -> keys.add(c.getPublicKey()));
        return keys;
    }

    private static boolean issuedBy(final X509Certificate cert, final X509Certificate issuer) {
        return cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
                && verifies(cert, issuer.getPublicKey());
    }

    private static boolean verifies(final X509Certificate cert, final PublicKey key) {
        if (key == null) {
            return false;
        }
        try {
            cert.verify(key);
            return true;
        } catch (final GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static X509Certificate parse(final byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (final GeneralSecurityException | RuntimeException e) {
            throw refused("MSO status_list certificate cannot be parsed");
        }
    }

    private static WalletVerificationException refused(final String safeDetail) {
        return new WalletVerificationException(WalletErrorCode.STATUS_UNAVAILABLE, safeDetail);
    }
}
