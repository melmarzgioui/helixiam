/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * The set of user claims/attributes Helix supports out of the box. Admins pick from this fixed list
 * at the user level (never inventing keys), so the same concept is never stored under two different
 * keys. New claim *types* are added at claim-management level, not per user — extend this catalogue.
 */
export interface ClaimDef {
  /** The stable attribute key persisted on the user (and emitted as the OIDC claim). */
  key: string;
  label: string;
  placeholder?: string;
  /** Grouping for the picker. */
  group: "Profile" | "Contact" | "Organisation" | "eID";
}

export const SUPPORTED_CLAIMS: ClaimDef[] = [
  { key: "given_name", label: "Given name", group: "Profile", placeholder: "Alice" },
  { key: "family_name", label: "Family name", group: "Profile", placeholder: "de Vries" },
  { key: "preferred_username", label: "Preferred username", group: "Profile" },
  { key: "locale", label: "Locale", group: "Profile", placeholder: "nl-NL" },
  { key: "email", label: "Email", group: "Contact", placeholder: "alice@organisation.nl" },
  { key: "phone_number", label: "Phone number", group: "Contact", placeholder: "+31 6 1234 5678" },
  { key: "department", label: "Department", group: "Organisation", placeholder: "Belastingdienst" },
  { key: "organization", label: "Organisation", group: "Organisation" },
  { key: "employee_id", label: "Employee ID", group: "Organisation" },
  { key: "bsn", label: "BSN (citizen)", group: "eID" },
  { key: "kvk_number", label: "KvK number (business)", group: "eID" },
];

const BY_KEY = new Map(SUPPORTED_CLAIMS.map((c) => [c.key, c]));

export function claimLabel(key: string): string {
  return BY_KEY.get(key)?.label ?? key;
}

export function claimDef(key: string): ClaimDef | undefined {
  return BY_KEY.get(key);
}
