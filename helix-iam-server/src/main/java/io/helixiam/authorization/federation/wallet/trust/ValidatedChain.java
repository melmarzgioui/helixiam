/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import java.security.PublicKey;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * A certificate chain as {@link IssuerTrustValidator#validateChain} proved it: the validated path (leaf first; trailing
 * anchor certificates removed, pinned intermediates added) and the trust anchor PKIX validated it to. Only this, never
 * the presented chain, may answer "who issued this certificate".
 */
public record ValidatedChain(List<X509Certificate> path, TrustAnchor anchor) {

    public ValidatedChain {
        path = List.copyOf(Objects.requireNonNull(path, "path"));
        Objects.requireNonNull(anchor, "anchor");
        if (path.isEmpty()) {
            throw new IllegalArgumentException("a validated path has at least its leaf");
        }
    }

    public X509Certificate leaf() {
        return path.get(0);
    }

    /** The certificate that issued the leaf: the next one on the path, or the anchor's certificate (null if key-only). */
    public X509Certificate leafIssuer() {
        return path.size() > 1 ? path.get(1) : anchor.getTrustedCert();
    }

    /** The public key that issued the leaf (also for a key-only anchor). */
    public PublicKey leafIssuerKey() {
        if (path.size() > 1) {
            return path.get(1).getPublicKey();
        }
        return anchor.getTrustedCert() != null ? anchor.getTrustedCert().getPublicKey() : anchor.getCAPublicKey();
    }

    /** Every issuing CA above the leaf, nearest first: the rest of the path, then the anchor (its certificate or key). */
    public List<PublicKey> issuerKeys() {
        final java.util.ArrayList<PublicKey> keys = new java.util.ArrayList<>();
        for (int i = 1; i < path.size(); i++) {
            keys.add(path.get(i).getPublicKey());
        }
        keys.add(anchor.getTrustedCert() != null ? anchor.getTrustedCert().getPublicKey() : anchor.getCAPublicKey());
        return keys;
    }
}
