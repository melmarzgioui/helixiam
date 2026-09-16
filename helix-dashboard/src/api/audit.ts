/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** Sanitized audit/SIEM delivery config from the E8.5 Events admin API (never includes the auth secret). */
export interface AuditConfig {
  enabled: boolean;
  transports: string[];
  httpUrl: string | null;
  httpConfigured: boolean;
  authConfigured: boolean;
  categories: string[];
  timeoutMs: number;
}

/** B3: one persisted audit event from the searchable in-product log. */
export interface AuditRecord {
  ts: string | null;
  kind: string | null;
  category: string | null;
  type: string | null;
  realm: string | null;
  actor: string | null;
  sourceIp: string | null;
  resourceType: string | null;
  resourceId: string | null;
  outcome: string | null;
  detail: string | null;
}

export interface AuditPage {
  items: AuditRecord[];
  total: number;
  page: number;
  size: number;
}

/** Optional filters for the audit search; blank/undefined values match everything. */
export interface AuditFilters {
  type?: string;
  actor?: string;
  outcome?: string;
  category?: string;
  page?: number;
  size?: number;
}

export interface AuditApi {
  getConfig(): Promise<AuditConfig>;
  /** B3: realm-scoped, paged, filtered search of the persisted audit log. */
  search(realmId: string, filters?: AuditFilters): Promise<AuditPage>;
}

/** HTTP-backed client for the E8.5 audit config endpoint (global) + B3 per-realm event search. */
export function createAuditHttpClient(baseUrl = ""): AuditApi {
  const base = baseUrl.replace(/\/$/, "");
  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  };
  return {
    getConfig: () => fetch(`${base}/admin/audit/config`).then(json),
    search: (realmId, filters = {}) => {
      const q = new URLSearchParams();
      if (filters.type) q.set("type", filters.type);
      if (filters.actor) q.set("actor", filters.actor);
      if (filters.outcome) q.set("outcome", filters.outcome);
      if (filters.category) q.set("category", filters.category);
      q.set("page", String(filters.page ?? 0));
      q.set("size", String(filters.size ?? 50));
      return fetch(`${base}/admin/realms/${encodeURIComponent(realmId)}/events?${q.toString()}`).then(json);
    },
  };
}
