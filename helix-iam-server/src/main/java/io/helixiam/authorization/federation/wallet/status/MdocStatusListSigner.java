/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.status;

import io.helixiam.authorization.federation.wallet.WalletErrorCode;
import io.helixiam.authorization.federation.wallet.WalletVerificationException;
import io.helixiam.authorization.federation.wallet.trust.ValidatedChain;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Who may sign the Token Status List of an mdoc (ISO/IEC 18013-5 2nd ed. draft §12.3.6.2, docs/eudi-wallet-spec-notes.md
 * §6.5; controller ruling, Task 19 fix round 1). Both chains are the ones PKIX <em>validated</em> (the list's against the
 * provider's anchors by {@link StatusListToken}, the MSO's by the mdoc verifier): never the presented x5chain, which an
 * attacker can pad with another issuer's anchor.
 *
 * <ul>
 *   <li><b>Without</b> {@code status_list.certificate}: the list must be signed by the MSO signer itself, or chain (on its
 *       validated path or to its anchor) to the MSO signer's <em>own issuing CA</em>, the certificate that issued the
 *       IssuerAuth document-signer certificate. Sharing only a higher root is not enough: a sibling issuing CA under the
 *       same root is refused.</li>
 *   <li><b>With</b> it: that certificate is the trust point. The list must be signed by it or chain to it on its
 *       validated path or anchor, and (already checked) still to the provider's anchors.</li>
 * </ul>
 * A refusal is {@code STATUS_UNAVAILABLE}: an integrity failure of the list, never subject to {@code onUnavailable}.
 */
final class MdocStatusListSigner {

    private MdocStatusListSigner() {
    }

    /** @throws WalletVerificationException {@code STATUS_UNAVAILABLE} when the list signer is not bound to the issuer */
    static void check(final ValidatedChain list, final CredentialIssuer issuer) {
        if (list == null) {
            throw refused("Status List Token has no validated signer");
        }
        final byte[] certificate = issuer.statusListCertificate();
        if (certificate != null) {
            final X509Certificate point = parse(certificate);
            if (!list.leaf().equals(point) && !chainsTo(list, point.getPublicKey())) {
                throw refused("Status List Token signer does not chain to the MSO status_list certificate");
            }
            return;
        }
        final ValidatedChain mso = issuer.validated();
        if (list.leaf().equals(mso.leaf()) || chainsTo(list, mso.leafIssuerKey())) {
            return;
        }
        throw refused("Status List Token is not signed under the MSO signer's issuing CA");
    }

    /** Whether {@code key} issues some certificate of the list's validated path, or is its anchor. */
    private static boolean chainsTo(final ValidatedChain list, final PublicKey key) {
        if (key == null) {
            return false;
        }
        return list.issuerKeys().stream().anyMatch(k -> k != null && Arrays.equals(k.getEncoded(), key.getEncoded()));
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
