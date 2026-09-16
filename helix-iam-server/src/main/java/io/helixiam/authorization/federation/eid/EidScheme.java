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
    DIGID
}
