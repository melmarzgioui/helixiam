/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.common.net;

import java.util.Map;
import java.util.Properties;

/**
 * Bounded defaults for the JDK's own certificate-revocation fetches (OCSP and CRL distribution points). The wallet
 * issuer-trust validator no longer lets the JDK fetch (it uses {@code IssuerRevocationClient} over
 * {@link PinnedHttpFetcher}), so these bound only a JDK fetch that some other PKIX revocation use might still make;
 * they stay as defence in depth. The JDK defaults are 15 s each. The JDK reads these system properties once, in static
 * initialisers, so {@link #applyDefaults} must run in {@code main} before anything touches PKIX revocation. A value the
 * operator passed with {@code -D} is kept.
 */
public final class RevocationTimeouts {

    /** Seconds; connect timeouts 3 s, read timeouts 5 s. */
    static final Map<String, String> DEFAULTS = Map.of(
            "com.sun.security.ocsp.timeout", "3",
            "com.sun.security.crl.timeout", "3",
            "com.sun.security.ocsp.readtimeout", "5",
            "com.sun.security.crl.readtimeout", "5");

    private RevocationTimeouts() {
    }

    /** Sets each default in {@code props} (normally {@link System#getProperties()}) only when it is absent. */
    public static void applyDefaults(final Properties props) {
        DEFAULTS.forEach(props::putIfAbsent);
    }
}
