package group.mfnr.authorization.federation.eid;

import java.util.Map;

/**
 * Helix IAM E6: maps a SAML {@code AuthnContextClassRef} URN to its rung on the scheme's
 * level-of-assurance ladder and decides whether an asserted level meets a configured minimum. Each
 * scheme has its own ordered URNs:
 *
 * <ul>
 *   <li><b>eIDAS</b> — low (1) / substantial (2) / high (3) via {@code http://eidas.europa.eu/LoA/*}.</li>
 *   <li><b>DigiD</b> — the NL eID-stelsel ladder {@code urn:nl-eid-gdi:1.0:LoA:Low|Substantial|High}
 *       (the exact AuthnContextClassRef values are operator/service-catalog driven; DigiD "Midden"
 *       sits between Low and Substantial and is mapped here when present).</li>
 *   <li><b>eHerkenning</b> — LoA2 (2) / LoA3 (3) / LoA4 (4) via the {@code urn:etoegang} classes.</li>
 * </ul>
 *
 * Comparison is by rung, so it is independent of the exact URN strings. An unknown/blank asserted
 * level is rung 0 and meets no minimum; a blank minimum means "any successful level is acceptable".
 */
public final class EidLevelOfAssurance {

    private static final Map<EidScheme, Map<String, Integer>> LADDERS = Map.of(
            EidScheme.EIDAS, Map.of(
                    "http://eidas.europa.eu/LoA/low", 1,
                    "http://eidas.europa.eu/LoA/substantial", 2,
                    "http://eidas.europa.eu/LoA/high", 3),
            EidScheme.DIGID, Map.of(
                    "urn:nl-eid-gdi:1.0:LoA:Low", 1,            // Basis
                    "urn:nl-eid-gdi:1.0:LoA:Midden", 2,         // Midden
                    "urn:nl-eid-gdi:1.0:LoA:Substantial", 3,    // Substantieel
                    "urn:nl-eid-gdi:1.0:LoA:High", 4),          // Hoog
            EidScheme.EHERKENNING, Map.of(
                    "urn:etoegang:core:assurance-class:loa2", 2,
                    "urn:etoegang:core:assurance-class:loa2plus", 2,
                    "urn:etoegang:core:assurance-class:loa3", 3,
                    "urn:etoegang:core:assurance-class:loa4", 4));

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
     * Whether {@code asserted} is at least as strong as {@code minimum}. A blank minimum is always
     * met; a blank/unknown asserted level never meets a non-blank minimum.
     */
    public static boolean meetsMinimum(final EidScheme scheme, final String asserted, final String minimum) {
        if (minimum == null || minimum.isBlank()) {
            return true;
        }
        return rung(scheme, asserted) >= rung(scheme, minimum) && rung(scheme, asserted) > 0;
    }
}
