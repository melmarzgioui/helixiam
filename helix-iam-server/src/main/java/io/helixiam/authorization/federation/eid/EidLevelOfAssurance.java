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
 *   <li><b>DigiD</b> — the SAML 2.0 context classes of Logius, <i>Koppelvlakspecificatie DigiD SAML
 *       Authenticatie</i> v3.5: PasswordProtectedTransport (Basis), MobileTwoFactorContract (Midden), Smartcard
 *       (Substantieel), SmartcardPKI (Hoog). Every DigiD console keyword resolves to one of these, so it is what the
 *       AuthnRequest asks for. The NL eID-stelsel URNs {@code urn:nl-eid-gdi:1.0:LoA:Low|Midden|Substantial|High}
 *       stay on the ladder at the same rungs, for brokers that assert them.</li>
 *   <li><b>eHerkenning</b> — LoA2 / LoA2+ / LoA3 / LoA4 via the {@code urn:etoegang} classes.</li>
 * </ul>
 *
 * Rungs are spaced by 10 so a level can sit between two others (eHerkenning EH2+ is 25: above EH2, below EH3).
 * Comparison is by rung, so it is independent of the exact URN strings. An unknown/blank asserted
 * level is rung 0 and meets no minimum; a blank minimum means "any successful level is acceptable".
 * A configured minimum may also be the short keyword the admin console stores ({@code loa1}..{@code loa4}
 * or {@code basis}/{@code midden}/{@code substantieel}/{@code hoog} for DigiD, {@code loa2}/{@code loa2plus}/{@code loa3}/{@code loa4} for eHerkenning, {@code low}/{@code
 * substantial}/{@code high} for eIDAS). An unrecognised non-blank minimum is never met (fail closed) and is
 * refused when a connection is saved or built.
 */
public final class EidLevelOfAssurance {

    private static final String DIGID_BASIS = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
    private static final String DIGID_MIDDEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";
    private static final String DIGID_SUBSTANTIEEL = "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard";
    private static final String DIGID_HOOG = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI";

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
                    // Logius, Koppelvlakspecificatie DigiD SAML Authenticatie v3.5: the SAML 2.0 context classes.
                    DIGID_BASIS, 10,
                    DIGID_MIDDEN, 20,
                    DIGID_SUBSTANTIEEL, 30,
                    DIGID_HOOG, 40),
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
            // DigiD keywords resolve to the context classes of the Logius Koppelvlakspecificatie DigiD SAML
            // Authenticatie v3.5, which the AuthnRequest then asks for with Comparison="minimum".
            EidScheme.DIGID, Map.of(
                    "loa1", DIGID_BASIS,
                    "basis", DIGID_BASIS,
                    "loa2", DIGID_MIDDEN,
                    "midden", DIGID_MIDDEN,
                    "loa3", DIGID_SUBSTANTIEEL,
                    "substantieel", DIGID_SUBSTANTIEEL,
                    "loa4", DIGID_HOOG,
                    "hoog", DIGID_HOOG),
            EidScheme.EHERKENNING, Map.of(
                    "loa2", "urn:etoegang:core:assurance-class:loa2",
                    "loa2plus", "urn:etoegang:core:assurance-class:loa2plus",
                    "loa3", "urn:etoegang:core:assurance-class:loa3",
                    "loa4", "urn:etoegang:core:assurance-class:loa4"));

    private EidLevelOfAssurance() {
    }

    /**
     * The rung of this AuthnContextClassRef on the scheme's ladder, or {@code 0} if unrecognised/blank.
     * {@link EidScheme#EUDI_WALLET} is an audit/display tag only — it has no ladder of its own and
     * delegates to {@link EidScheme#EIDAS}'s.
     */
    public static int rung(final EidScheme scheme, final String authnContextClassRef) {
        if (authnContextClassRef == null || authnContextClassRef.isBlank()) {
            return 0;
        }
        final EidScheme ladderScheme = scheme == EidScheme.EUDI_WALLET ? EidScheme.EIDAS : scheme;
        return LADDERS.getOrDefault(ladderScheme, Map.of()).getOrDefault(authnContextClassRef.trim(), 0);
    }

    /**
     * The scheme URN for a configured minimum: the URN itself when it is on the ladder, the URN a console
     * keyword stands for, or {@code null} when the value is blank or not recognised for this scheme. Like
     * {@link #rung}, {@link EidScheme#EUDI_WALLET} resolves on the eIDAS ladder (it has none of its own).
     */
    public static String canonicalMinimum(final EidScheme scheme, final String minimum) {
        if (minimum == null || minimum.isBlank()) {
            return null;
        }
        final EidScheme ladderScheme = scheme == EidScheme.EUDI_WALLET ? EidScheme.EIDAS : scheme;
        final String value = minimum.trim();
        if (LADDERS.getOrDefault(ladderScheme, Map.of()).containsKey(value)) {
            return value;
        }
        return KEYWORDS.getOrDefault(ladderScheme, Map.of()).get(value.toLowerCase(java.util.Locale.ROOT));
    }

    /** DigiD: the Logius v3.5 context class of each rung, for the AuthnRequest. */
    private static final Map<Integer, String> DIGID_REQUEST_CLASS = Map.of(
            10, DIGID_BASIS, 20, DIGID_MIDDEN, 30, DIGID_SUBSTANTIEEL, 40, DIGID_HOOG);

    /**
     * The {@code AuthnContextClassRef} to put in the AuthnRequest for a configured minimum, or {@code null} when it is
     * blank or unknown. For DigiD it is always the Logius v3.5 context class of the minimum's rung: a minimum stored as an
     * {@code urn:nl-eid-gdi:1.0:LoA:*} URN is requested as the oasis class of the same level, since DigiD does not
     * know those URNs in a request. For the other schemes it is {@link #canonicalMinimum}. The comparison of the
     * asserted level ({@link #meetsMinimum}) is not affected.
     */
    public static String requestedClass(final EidScheme scheme, final String minimum) {
        final String canonical = canonicalMinimum(scheme, minimum);
        if (canonical == null || scheme != EidScheme.DIGID) {
            return canonical;
        }
        return DIGID_REQUEST_CLASS.getOrDefault(rung(scheme, canonical), canonical);
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
