/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Helix IAM GDPR Art. 15/17/7: admin-console client for the data-subject-rights API. All calls are
 * realm + user scoped (the URL carries both ids), matching the backend at
 * {@code /admin/realms/{realm}/users/{userId}/gdpr/**}. Same-origin (admin session cookie); errors throw.
 */

/** GDPR Art. 7: one entry in a user's consent ledger (a grant, possibly later withdrawn). */
export interface GdprConsentRecord {
  id: string;
  realmId: string;
  userId: string;
  clientId: string;
  scopes: string[];
  grantedAt: number | null;
  withdrawnAt: number | null;
}

/**
 * GDPR Art. 15/20: a user's full data export. Deliberately open-ended (the backend may add slices); the
 * page renders it as JSON and offers a download, so it does not need a tight type for every nested field.
 */
export interface GdprExport {
  generatedAt: number | null;
  schema: string;
  realmId: string;
  userId: string;
  profile: Record<string, unknown> | null;
  attributes: Record<string, string>;
  roles: string[];
  realmMemberships: unknown[];
  organizations: unknown[];
  credentials: unknown[];
  federatedLinks: unknown[];
  consents: GdprConsentRecord[];
  loginEvents: unknown[];
}

/** Outcome of an Art. 17 erasure. */
export interface GdprEraseResult {
  found: boolean;
  mode: string;
  userId: string;
}

export type GdprEraseMode = "anonymize" | "hard";

export interface GdprApi {
  export(realmId: string, userId: string): Promise<GdprExport>;
  consents(realmId: string, userId: string): Promise<GdprConsentRecord[]>;
  erase(realmId: string, userId: string, mode: GdprEraseMode): Promise<GdprEraseResult>;
}

export function createGdprHttpClient(baseUrl = ""): GdprApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string, userId: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/users/${encodeURIComponent(userId)}/gdpr`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    export: (realmId, userId) => fetch(`${root(realmId, userId)}/export`).then(json),
    consents: (realmId, userId) => fetch(`${root(realmId, userId)}/consents`).then(json),
    erase: (realmId, userId, mode) =>
      fetch(`${root(realmId, userId)}?mode=${encodeURIComponent(mode)}`, { method: "DELETE" }).then(json),
  };
}

/** In-memory client for stories/tests. */
export function createGdprMemoryClient(seed?: Partial<GdprExport>): GdprApi {
  const sample: GdprExport = {
    generatedAt: Date.now(),
    schema: "helix.gdpr.export/v1",
    realmId: "master",
    userId: "mem-1",
    profile: { username: "ada", email: "ada@example.com", enabled: true, locked: false, mfaEnabled: true },
    attributes: { department: "research" },
    roles: ["user"],
    realmMemberships: [{ realmId: "master", joinedAt: null }],
    organizations: [],
    credentials: [{ type: "passkey", id: "abc", label: "Passkey (FIDO2)" }],
    federatedLinks: [],
    consents: [],
    loginEvents: [],
    ...seed,
  };
  return {
    export: async () => sample,
    consents: async () => sample.consents,
    erase: async (_realmId, userId, mode) => ({ found: true, mode, userId }),
  };
}
