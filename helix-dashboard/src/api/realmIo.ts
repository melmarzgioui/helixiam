/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Helix IAM: realm import/export API client. Mirrors the create*HttpClient factory style of the other
// api/*.ts modules. The realm is always carried in the path; secrets are masked server-side on export.

/** One slice's outcome in an import. */
export interface SliceSummary {
  created: number;
  updated: number;
  skipped: number;
}

/** The per-slice import result the console renders. */
export interface RealmImportResult {
  realm: string;
  slices: Record<string, SliceSummary>;
}

/**
 * The export document. Loosely typed on purpose: the console previews slice counts and round-trips the
 * document verbatim on import, so it does not need the full per-field shape (which the backend owns).
 */
export interface RealmExportDocument {
  formatVersion?: number;
  realm?: unknown;
  clients?: unknown[];
  samlClients?: unknown[];
  roles?: unknown[];
  clientScopes?: unknown[];
  identityProviders?: unknown[];
  flows?: unknown[];
  organizations?: unknown[];
  [key: string]: unknown;
}

/** How an entry whose natural key already exists is treated on import. */
export type OnConflict = "overwrite" | "skip" | "fail";

/** The full import result, including any conflicts reported in `fail` mode. */
export interface RealmImportResultFull extends RealmImportResult {
  conflicts?: string[];
}

export interface RealmIoApi {
  /** Fetches the full secret-masked export document for a realm. */
  exportRealm(realmId: string): Promise<RealmExportDocument>;
  /** Idempotently imports a document into a realm; returns the per-slice summary. `onConflict` controls
   * whether existing entries are overwritten (default), skipped, or fail the apply. */
  importRealm(realmId: string, document: RealmExportDocument, onConflict?: OnConflict): Promise<RealmImportResultFull>;
  /**
   * Migrate off Keycloak: POSTs a raw Keycloak realm-export JSON, which the backend translates (OIDC
   * clients with derived grant types, realm roles, identity providers) and upserts. Users are not
   * migrated — Keycloak password hashes aren't portable; bring them via SCIM / LDAP / bulk import.
   */
  importKeycloak(realmId: string, keycloakExport: unknown): Promise<RealmImportResult>;
}

export function createRealmIoHttpClient(baseUrl = ""): RealmIoApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}`;

  const json = async (res: Response) => {
    if (!res.ok) {
      // Surface the AdminValidationAdvice {message,fieldErrors} body when present.
      let message = `${res.status} ${res.statusText}`;
      try {
        const body = await res.json();
        if (body && typeof body.message === "string") message = body.message;
      } catch {
        /* non-JSON error body — keep the status line */
      }
      throw new Error(message);
    }
    return res.json();
  };

  return {
    exportRealm: (realmId) => fetch(`${root(realmId)}/export`).then(json),
    importRealm: (realmId, document, onConflict) =>
      fetch(`${root(realmId)}/import${onConflict ? `?onConflict=${encodeURIComponent(onConflict)}` : ""}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(document),
      }).then(json),
    importKeycloak: (realmId, keycloakExport) =>
      fetch(`${root(realmId)}/import/keycloak`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(keycloakExport),
      }).then(json),
  };
}
