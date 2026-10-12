/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.helixiam.authorization.federation.eid;

/**
 * Helix IAM E6: the EU/NL government identity schemes Helix brokers out of the box. All three are
 * SAML2 SP profiles (atop the E5.2 SAML broker) that add encrypted assertions, level-of-assurance
 * enforcement, and signed AuthnRequests, but differ in their LoA ladders and subject attributes
 * (eIDAS PersonIdentifier, DigiD BSN, eHerkenning KvK/entityConcernedID).
 */
public enum EidScheme {

    /** eIDAS — cross-border EU citizen login via a national eIDAS node. */
    EIDAS,

    /** eHerkenning — NL business eID via a broker (makelaar). */
    EHERKENNING,

    /** DigiD — NL citizen eID via Logius. */
    DIGID;

    /**
     * The scheme of a stored connection: its {@code scheme} setting when set, else its protocol
     * ({@code eid} means DigiD).
     *
     * @throws IllegalArgumentException when the value names no scheme
     */
    public static EidScheme of(final String protocol, final String override) {
        final String value = override == null || override.isBlank() ? protocol : override;
        return switch (value == null ? "" : value.toLowerCase(java.util.Locale.ROOT)) {
            case "eidas" -> EIDAS;
            case "eherkenning" -> EHERKENNING;
            case "digid", "eid" -> DIGID;
            default -> throw new IllegalArgumentException("Unknown eID scheme: " + value);
        };
    }

    /** Whether a stored connection's protocol is one of the eID schemes. */
    public static boolean isEidProtocol(final String protocol) {
        return protocol != null && switch (protocol.toLowerCase(java.util.Locale.ROOT)) {
            case "eid", "digid", "eherkenning", "eidas" -> true;
            default -> false;
        };
    }
}
