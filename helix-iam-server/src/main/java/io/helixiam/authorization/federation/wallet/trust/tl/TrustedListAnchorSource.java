/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.wallet.trust.tl;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * What a wallet provider asks of the trusted lists: the certificates of the named sources of its realm that may be
 * trust anchors right now (current services of the source, narrowed to {@code serviceTypes} when given, from a list
 * still inside its NextUpdate plus grace), and whether a source name exists (for config validation).
 */
public interface TrustedListAnchorSource {

    /** No trusted lists (tests, or a server without a database): no anchors, and every name is accepted. */
    TrustedListAnchorSource NONE = new TrustedListAnchorSource() {
        @Override
        public List<X509Certificate> anchors(final String realm, final List<String> sources,
                                             final List<String> serviceTypes) {
            return List.of();
        }

        @Override
        public boolean exists(final String realm, final String name) {
            return true;
        }
    };

    /** The usable anchor certificates of {@code sources} (names) in {@code realm}; never null. */
    List<X509Certificate> anchors(String realm, List<String> sources, List<String> serviceTypes);

    /** Whether {@code realm} has a trusted list source named {@code name}. */
    boolean exists(String realm, String name);
}
