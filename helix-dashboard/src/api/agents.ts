/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A first-class agent / non-human identity (NHI). Authenticates via its bound OIDC client; lifecycle is
 * the kill-switch. No secret is carried on this object — agents authenticate through their bound client. */
export interface Agent {
  id: string;
  realmId: string;
  name: string;
  displayName: string | null;
  description: string | null;
  owner: string;
  status: string; // ACTIVE | SUSPENDED | EXPIRED | REVOKED
  authMethod: string; // FEDERATED | SECRET | JWT
  clientId: string | null;
  scopes: string | null;
  /** The agent's OWN least-privilege realm roles (CSV); unioned into its tokens. Never the owner's roles. */
  roles: string | null;
  enabled: boolean;
  createdAt: number | null;
  expiresAt: number | null;
  lastUsedAt: number | null;
}

export interface AgentWrite {
  name: string;
  displayName?: string | null;
  description?: string | null;
  owner: string;
  status?: string;
  authMethod?: string;
  clientId?: string | null;
  scopes?: string | null;
  roles?: string | null;
  enabled?: boolean;
  expiresAt?: number | null;
}

/** One row of the owner-integrity review: an agent + the verdict on its accountable-human owner. */
export type OwnerStatus = "VALID" | "UNKNOWN" | "ORPHANED";
export interface AgentOwnerReview {
  id: string;
  name: string;
  owner: string;
  status: string;
  ownerStatus: OwnerStatus;
}

/** How many agents have an owner problem (a fictional UNKNOWN owner or an ORPHANED/zombie owner). */
export function ownerIssueCount(reviews: AgentOwnerReview[]): number {
  return reviews.filter((r) => r.ownerStatus !== "VALID").length;
}

/** Index the review by agent id → owner status, for tagging rows/drawer without a second lookup. */
export function ownerStatusById(reviews: AgentOwnerReview[]): Record<string, OwnerStatus> {
  const map: Record<string, OwnerStatus> = {};
  for (const r of reviews) map[r.id] = r.ownerStatus;
  return map;
}

export interface AgentApi {
  list(realmId: string): Promise<Agent[]>;
  ownerReview(realmId: string): Promise<AgentOwnerReview[]>;
  create(realmId: string, body: AgentWrite): Promise<Agent>;
  update(realmId: string, id: string, body: AgentWrite): Promise<Agent>;
  remove(realmId: string, id: string): Promise<void>;
  suspend(realmId: string, id: string): Promise<Agent>;
  activate(realmId: string, id: string): Promise<Agent>;
  revoke(realmId: string, id: string): Promise<Agent>;
}

/** Governance rollup for the NHI inventory: how many agents, and how many need attention. */
export interface AgentStats {
  total: number;
  active: number;
  suspended: number;
  revoked: number;
  expired: number;
  /** Active agents whose credential expires within the next 14 days — the rotation/renewal worklist. */
  expiringSoon: number;
}

/** Days ahead within which an active agent's expiry counts as "expiring soon". */
export const EXPIRING_SOON_DAYS = 14;

/** Pure governance rollup over the agent list — the numbers behind the inventory overview strip. */
export function agentStats(agents: Agent[], nowMs: number): AgentStats {
  const soonBefore = nowMs + EXPIRING_SOON_DAYS * 86_400_000;
  const s: AgentStats = { total: agents.length, active: 0, suspended: 0, revoked: 0, expired: 0, expiringSoon: 0 };
  for (const a of agents) {
    if (a.status === "ACTIVE") s.active++;
    else if (a.status === "SUSPENDED") s.suspended++;
    else if (a.status === "REVOKED") s.revoked++;
    else if (a.status === "EXPIRED") s.expired++;
    if (a.status === "ACTIVE" && a.expiresAt != null && a.expiresAt > nowMs && a.expiresAt <= soonBefore) {
      s.expiringSoon++;
    }
  }
  return s;
}

/** Split a CSV/whitespace list (scopes, roles) into trimmed, non-empty tokens for rendering as chips. */
export function parseCsv(value: string | null | undefined): string[] {
  return (value ?? "").split(/[,\s]+/).map((t) => t.trim()).filter(Boolean);
}

/** One page of a client-side paginated list, with the page index clamped into range. */
export interface PageOf<T> {
  items: T[];
  page: number;
  pageCount: number;
  total: number;
}

/** Pure client-side pagination: slice `items` to page `page` (0-based) of `size`, clamping out-of-range pages. */
export function paginate<T>(items: T[], page: number, size: number): PageOf<T> {
  const total = items.length;
  const pageCount = Math.max(1, Math.ceil(total / size));
  const clamped = Math.min(Math.max(0, page), pageCount - 1);
  const start = clamped * size;
  return { items: items.slice(start, start + size), page: clamped, pageCount, total };
}

/** Pure validator: an agent needs a name (no spaces) and an accountable owner. Returns failing field keys. */
export function validateAgent(a: AgentWrite): string[] {
  const errors: string[] = [];
  if (!/^[A-Za-z0-9._:-]+$/.test((a.name ?? "").trim())) errors.push("name");
  if (!(a.owner ?? "").trim()) errors.push("owner");
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

/** HTTP-backed client for the agent (NHI) admin REST API. */
export function createAgentsHttpClient(baseUrl = ""): AgentApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, id?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/agents${id ? `/${encodeURIComponent(id)}` : ""}`;
  const lifecycle = (realmId: string, id: string, action: string) =>
    send(`${url(realmId, id)}/${action}`, "POST");
  return {
    list: (realmId) => send(url(realmId), "GET"),
    ownerReview: (realmId) => send(`${url(realmId)}/owner-review`, "GET"),
    create: (realmId, body) => send(url(realmId), "POST", body),
    update: (realmId, id, body) => send(url(realmId, id), "PUT", body),
    remove: (realmId, id) => send(url(realmId, id), "DELETE").then(() => undefined),
    suspend: (realmId, id) => lifecycle(realmId, id, "suspend"),
    activate: (realmId, id) => lifecycle(realmId, id, "activate"),
    revoke: (realmId, id) => lifecycle(realmId, id, "revoke"),
  };
}
