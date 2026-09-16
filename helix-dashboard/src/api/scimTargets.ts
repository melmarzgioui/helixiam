/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A per-realm outbound SCIM 2.0 provisioning target (B7). The bearer token is write-only — never returned. */
export interface ScimTarget {
  id: string;
  realmId: string;
  name: string | null;
  /** The downstream SCIM service-provider base URL (the /Users collection hangs off it). */
  baseUrl: string;
  /** Always null on read; whether a token is set is conveyed by `tokenSet`. */
  token: string | null;
  tokenSet: boolean;
  /** Comma-joined user-event allow-list (USER_CREATE/USER_UPDATE/USER_DELETE); blank = all user events. */
  eventTypes: string;
  enabled: boolean;
  createdAt: number | null;
}

export interface ScimTargetWrite {
  name?: string | null;
  baseUrl: string;
  /** Leave blank on edit to keep the existing token. */
  token?: string | null;
  eventTypes?: string;
  enabled?: boolean;
}

export interface ScimTargetApi {
  list(realmId: string): Promise<ScimTarget[]>;
  create(realmId: string, body: ScimTargetWrite): Promise<ScimTarget>;
  update(realmId: string, id: string, body: ScimTargetWrite): Promise<ScimTarget>;
  remove(realmId: string, id: string): Promise<void>;
}

/** The user lifecycle events an outbound SCIM target can sync. */
export const SCIM_EVENT_OPTIONS: { key: string; label: string }[] = [
  { key: "USER_CREATE", label: "User created" },
  { key: "USER_UPDATE", label: "User updated / enabled / disabled" },
  { key: "USER_DELETE", label: "User deleted" },
];

/** Pure validator: a SCIM target needs an absolute http(s) base URL. Returns failing field keys. */
export function validateScimTarget(t: ScimTargetWrite): string[] {
  const errors: string[] = [];
  if (!/^https?:\/\/.+/.test((t.baseUrl ?? "").trim())) errors.push("baseUrl");
  return errors;
}

function json(res: Response) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.status === 204 ? null : res.json();
}
const send = (url: string, method: string, body?: unknown) =>
  fetch(url, body === undefined
    ? { method }
    : { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json);

/** HTTP-backed client for the B7 outbound-SCIM admin REST API. */
export function createScimTargetHttpClient(baseUrl = ""): ScimTargetApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, id?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/scim-targets${id ? `/${encodeURIComponent(id)}` : ""}`;
  return {
    list: (realmId) => send(url(realmId), "GET"),
    create: (realmId, body) => send(url(realmId), "POST", body),
    update: (realmId, id, body) => send(url(realmId, id), "PUT", body),
    remove: (realmId, id) => send(url(realmId, id), "DELETE").then(() => undefined),
  };
}

/** In-memory client for stories/tests. */
export function createScimTargetMemoryClient(seed: ScimTarget[] = []): ScimTargetApi {
  const store = new Map<string, ScimTarget>();
  let seq = 0;
  seed.forEach((t) => store.set(t.id, t));
  return {
    list: async (realmId) => [...store.values()].filter((t) => t.realmId === realmId),
    create: async (realmId, body) => {
      const t: ScimTarget = {
        id: `mem-${++seq}`, realmId, name: body.name ?? null, baseUrl: body.baseUrl,
        token: null, tokenSet: !!body.token, eventTypes: body.eventTypes ?? "",
        enabled: body.enabled ?? true, createdAt: 0,
      };
      store.set(t.id, t);
      return t;
    },
    update: async (_realmId, id, body) => {
      const prev = store.get(id);
      if (!prev) throw new Error("404 Not Found");
      const next: ScimTarget = { ...prev, name: body.name ?? null, baseUrl: body.baseUrl,
        eventTypes: body.eventTypes ?? "", enabled: body.enabled ?? true,
        tokenSet: prev.tokenSet || !!body.token };
      store.set(id, next);
      return next;
    },
    remove: async (_realmId, id) => { store.delete(id); },
  };
}
