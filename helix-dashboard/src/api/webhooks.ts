/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A per-realm outbound webhook subscription (B6). The signing secret is write-only — never returned. */
export interface Webhook {
  id: string;
  realmId: string;
  name: string | null;
  url: string;
  /** Always null on read; whether a secret is set is conveyed by `secretSet`. */
  secret: string | null;
  secretSet: boolean;
  /** Comma-joined event-type/category allow-list; blank = all events. */
  eventTypes: string;
  enabled: boolean;
  createdAt: number | null;
}

export interface WebhookWrite {
  name?: string | null;
  url: string;
  /** Leave blank on edit to keep the existing secret. */
  secret?: string | null;
  eventTypes?: string;
  enabled?: boolean;
}

export interface WebhookApi {
  list(realmId: string): Promise<Webhook[]>;
  create(realmId: string, body: WebhookWrite): Promise<Webhook>;
  update(realmId: string, id: string, body: WebhookWrite): Promise<Webhook>;
  remove(realmId: string, id: string): Promise<void>;
}

/** Pure validator: a webhook needs an absolute http(s) URL. Returns failing field keys. */
export function validateWebhook(w: WebhookWrite): string[] {
  const errors: string[] = [];
  if (!/^https?:\/\/.+/.test((w.url ?? "").trim())) errors.push("url");
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

/** HTTP-backed client for the B6 webhooks admin REST API. */
export function createWebhookHttpClient(baseUrl = ""): WebhookApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, id?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/webhooks${id ? `/${encodeURIComponent(id)}` : ""}`;
  return {
    list: (realmId) => send(url(realmId), "GET"),
    create: (realmId, body) => send(url(realmId), "POST", body),
    update: (realmId, id, body) => send(url(realmId, id), "PUT", body),
    remove: (realmId, id) => send(url(realmId, id), "DELETE").then(() => undefined),
  };
}
