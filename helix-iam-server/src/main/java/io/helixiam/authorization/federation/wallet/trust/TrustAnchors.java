/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

/**
 * The issuer trust configuration of one wallet provider: the anchors credential issuers must chain to, optional
 * pinned intermediates, and how certificate revocation is checked. Loading (PEM) and validation are added in Task 7.
 */
public record TrustAnchors(Set<TrustAnchor> anchors, List<X509Certificate> pinnedIntermediates,
        RevocationMode revocation) {

    /** How issuer-certificate revocation (CRL/OCSP) is handled. */
    public enum RevocationMode { OFF, SOFT_FAIL, HARD_FAIL }
}
