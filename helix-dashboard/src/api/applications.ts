/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** An Application (Service Provider) — the protocol-agnostic parent that owns shared claims + login flow. */
export interface Application {
  realmId: string;
  /** Stable identifier, unique per realm — keys the protocol links. Shown only as the muted technical id. */
  name: string;
  /** Human-friendly label shown in the UI. null/blank = fall back to `name`. */
  displayName: string | null;
  description: string | null;
  /** Shared OIDC `sub` source claim; applies to whichever protocol the app uses. null = realm default. */
  subjectClaim: string | null;
  /** Shared login flow alias; applies to all the app's protocols. null = realm browser flow. */
  authFlowAlias: string | null;
  enabled: boolean;
}

export interface ApplicationWrite {
  name: string;
  displayName?: string | null;
  description?: string | null;
  subjectClaim?: string | null;
  authFlowAlias?: string | null;
  enabled?: boolean;
}

export interface ApplicationApi {
  list(realmId: string): Promise<Application[]>;
  get(realmId: string, name: string): Promise<Application>;
  create(realmId: string, body: ApplicationWrite): Promise<Application>;
  update(realmId: string, name: string, body: ApplicationWrite): Promise<Application>;
  remove(realmId: string, name: string): Promise<void>;
}

/** The surrogate key the backend uses to link a protocol record to its app (matches ApplicationEntity.key). */
export function applicationId(realmId: string, name: string): string {
  return `${realmId}|${name}`;
}

/**
 * The label to show for an app: its human display name, else the stable id — but NEVER a raw UUID/`dcr-…`
 * (a backfilled app whose id is a machine identifier shows "Unnamed application" instead).
 */
export function applicationLabel(app: Pick<Application, "name" | "displayName">): string {
  if (app.displayName && app.displayName.trim()) return app.displayName.trim();
  const uuid = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
  if (app.name && app.name.trim() && !uuid.test(app.name)) return app.name.trim();
  return "Unnamed application";
}

/** Field-level validation for the create-application form. Pure so it can be unit-tested. */
export function validateApplication(w: ApplicationWrite): Record<string, string> {
  const errors: Record<string, string> = {};
  if (!w.name?.trim()) {
    errors.name = "Name is required.";
  } else if (!/^[\w .@:/-]+$/.test(w.name.trim())) {
    errors.name = "Use letters, numbers, spaces or . _ - @ : /";
  }
  return errors;
}

/** HTTP-backed client for the Applications admin REST API. */
export function createApplicationHttpClient(baseUrl = ""): ApplicationApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, name?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/applications${name ? `/${encodeURIComponent(name)}` : ""}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId) => fetch(url(realmId)).then(json),
    get: (realmId, name) => fetch(url(realmId, name)).then(json),
    create: (realmId, body) =>
      fetch(url(realmId), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(json),
    update: (realmId, name, body) =>
      fetch(url(realmId, name), {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }).then(json),
    remove: (realmId, name) =>
      fetch(url(realmId, name), { method: "DELETE" })
        .then(json)
        .then(() => undefined),
  };
}
