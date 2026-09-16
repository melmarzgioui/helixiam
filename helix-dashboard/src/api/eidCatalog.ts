/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Facilitated defaults for the Dutch/EU eID schemes (DigiD, eHerkenning, eIDAS).
 *
 * These connections are SAML2 brokers (Helix is the Service Provider). The *protocol-standard* values
 * are constant across every deployment and are pre-filled here so an admin doesn't have to know them:
 *  - the assertion binding (HTTP-POST),
 *  - the default minimum level of assurance keyword (the backend maps it to the scheme's LoA URN),
 *  - the subject attribute that carries the legal identifier.
 *
 * The *operator-specific* values — the broker's SSO URL, IdP entity ID and signing certificate — vary by
 * the recognised broker (makelaar) you contract with and the environment (pre-production / production),
 * so they are intentionally left blank for the admin to paste from the broker's published metadata. We
 * never fabricate those endpoints.
 */
export const EID_SCHEMES = ["digid", "eherkenning", "eidas"] as const;
export type EidScheme = (typeof EID_SCHEMES)[number];

export function isEidScheme(protocol: string): protocol is EidScheme {
  return (EID_SCHEMES as readonly string[]).includes(protocol);
}

/** Standard, deployment-independent SAML defaults for an eID scheme. Endpoints stay empty by design. */
export function eidFacilitatedConfig(scheme: EidScheme): Record<string, string> {
  // responseBinding "post" = modern front-channel SAMLResponse to the ACS; classic DigiD switches this
  // to "artifact" (back-channel resolve) on the form. ARS URL stays operator-specific (left blank).
  const common = { binding: "post", responseBinding: "post", ssoUrl: "", idpEntityId: "" };
  switch (scheme) {
    case "digid":
      // BSN is delivered inside the (encrypted) NameID, so there is no separate subject attribute.
      return { ...common, scheme: "digid", minimumLoa: "loa3", subjectAttribute: "" };
    case "eherkenning":
      // The KvK number arrives as the eToegang EntityConcernedID.
      return { ...common, scheme: "eherkenning", minimumLoa: "loa3", subjectAttribute: "urn:etoegang:1.9:EntityConcernedID:KvKnr" };
    case "eidas":
      // The eIDAS minimum dataset uniquely identifies a person via the PersonIdentifier attribute.
      return { ...common, scheme: "eidas", minimumLoa: "substantial", subjectAttribute: "http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier" };
  }
}
