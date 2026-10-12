/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

import java.util.Map;

/**
 * Helix IAM E6: maps a SAML {@code AuthnContextClassRef} URN to its rung on the scheme's
 * level-of-assurance ladder and decides whether an asserted level meets a configured minimum. Each
 * scheme has its own ordered URNs:
 *
 * <ul>
 *   <li><b>eIDAS</b> — low / substantial / high via {@code http://eidas.europa.eu/LoA/*}.</li>
 *   <li><b>DigiD</b> — the NL eID-stelsel ladder {@code urn:nl-eid-gdi:1.0:LoA:Low|Substantial|High}
 *       (the exact AuthnContextClassRef values are operator/service-catalog driven; DigiD "Midden"
 *       sits between Low and Substantial and is mapped here when present), plus the SAML 2.0 context classes
 *       classic DigiD asserts: PasswordProtectedTransport (Basis), MobileTwoFactorContract (Midden),
 *       Smartcard (Substantieel), SmartcardPKI (Hoog).</li>
 *   <li><b>eHerkenning</b> — LoA2 / LoA2+ / LoA3 / LoA4 via the {@code urn:etoegang} classes.</li>
 * </ul>
 *
 * Rungs are spaced by 10 so a level can sit between two others (eHerkenning EH2+ is 25: above EH2, below EH3).
 * Comparison is by rung, so it is independent of the exact URN strings. An unknown/blank asserted
 * level is rung 0 and meets no minimum; a blank minimum means "any successful level is acceptable".
 * A configured minimum may also be the short keyword the admin console stores ({@code loa1}..{@code loa4}
 * for DigiD, {@code loa2}/{@code loa2plus}/{@code loa3}/{@code loa4} for eHerkenning, {@code low}/{@code
 * substantial}/{@code high} for eIDAS). An unrecognised non-blank minimum is never met (fail closed) and is
 * refused when a connection is saved or built.
 */
public final class EidLevelOfAssurance {

    private static final Map<EidScheme, Map<String, Integer>> LADDERS = Map.of(
            EidScheme.EIDAS, Map.of(
                    "http://eidas.europa.eu/LoA/low", 10,
                    "http://eidas.europa.eu/LoA/substantial", 20,
                    "http://eidas.europa.eu/LoA/high", 30),
            EidScheme.DIGID, Map.of(
                    "urn:nl-eid-gdi:1.0:LoA:Low", 10,            // Basis
                    "urn:nl-eid-gdi:1.0:LoA:Midden", 20,         // Midden
                    "urn:nl-eid-gdi:1.0:LoA:Substantial", 30,    // Substantieel
                    "urn:nl-eid-gdi:1.0:LoA:High", 40,           // Hoog
                    // Classic DigiD (Koppelvlak SAML) asserts SAML 2.0 context classes instead. Per Logius DigiD
                    // koppelvlak documentation — verify: no source in this repository confirms this mapping.
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", 10, // Basis
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract", 20,    // Midden
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", 30,                  // Substantieel
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI", 40),              // Hoog
            EidScheme.EHERKENNING, Map.of(
                    "urn:etoegang:core:assurance-class:loa2", 20,
                    "urn:etoegang:core:assurance-class:loa2plus", 25, // EH2+: above EH2, below EH3
                    "urn:etoegang:core:assurance-class:loa3", 30,
                    "urn:etoegang:core:assurance-class:loa4", 40));

    /** The console's short keywords for a minimum, mapped to the scheme's URN (matched case-insensitively). */
    private static final Map<EidScheme, Map<String, String>> KEYWORDS = Map.of(
            EidScheme.EIDAS, Map.of(
                    "low", "http://eidas.europa.eu/LoA/low",
                    "substantial", "http://eidas.europa.eu/LoA/substantial",
                    "high", "http://eidas.europa.eu/LoA/high"),
            EidScheme.DIGID, Map.of(
                    "loa1", "urn:nl-eid-gdi:1.0:LoA:Low",
                    "loa2", "urn:nl-eid-gdi:1.0:LoA:Midden",
                    "loa3", "urn:nl-eid-gdi:1.0:LoA:Substantial",
                    "loa4", "urn:nl-eid-gdi:1.0:LoA:High"),
            EidScheme.EHERKENNING, Map.of(
                    "loa2", "urn:etoegang:core:assurance-class:loa2",
                    "loa2plus", "urn:etoegang:core:assurance-class:loa2plus",
                    "loa3", "urn:etoegang:core:assurance-class:loa3",
                    "loa4", "urn:etoegang:core:assurance-class:loa4"));

    private EidLevelOfAssurance() {
    }

    /** The rung of this AuthnContextClassRef on the scheme's ladder, or {@code 0} if unrecognised/blank. */
    public static int rung(final EidScheme scheme, final String authnContextClassRef) {
        if (authnContextClassRef == null || authnContextClassRef.isBlank()) {
            return 0;
        }
        return LADDERS.getOrDefault(scheme, Map.of()).getOrDefault(authnContextClassRef.trim(), 0);
    }

    /**
     * The scheme URN for a configured minimum: the URN itself when it is on the ladder, the URN a console
     * keyword stands for, or {@code null} when the value is blank or not recognised for this scheme.
     */
    public static String canonicalMinimum(final EidScheme scheme, final String minimum) {
        if (minimum == null || minimum.isBlank()) {
            return null;
        }
        final String value = minimum.trim();
        if (LADDERS.getOrDefault(scheme, Map.of()).containsKey(value)) {
            return value;
        }
        return KEYWORDS.getOrDefault(scheme, Map.of()).get(value.toLowerCase(java.util.Locale.ROOT));
    }

    /** Whether {@code minimum} may be configured for this scheme: blank (no minimum) or a recognised level. */
    public static boolean isValidMinimum(final EidScheme scheme, final String minimum) {
        return minimum == null || minimum.isBlank() || canonicalMinimum(scheme, minimum) != null;
    }

    /**
     * Whether {@code asserted} is at least as strong as {@code minimum}. A blank minimum is always
     * met; a blank/unknown asserted level never meets a non-blank minimum, and an unrecognised
     * non-blank minimum is never met (fail closed: it must not lower the bar to "any level").
     */
    public static boolean meetsMinimum(final EidScheme scheme, final String asserted, final String minimum) {
        if (minimum == null || minimum.isBlank()) {
            return true;
        }
        final int required = rung(scheme, canonicalMinimum(scheme, minimum));
        if (required == 0) {
            return false;
        }
        return rung(scheme, asserted) >= required;
    }
}
