/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A realm user as returned by the E8.5 Users admin API. */
export interface UserSummary {
  realmId: string;
  userId: string;
  username: string;
  /** Optional email; a user can sign in with either their username or this address. */
  email: string | null;
  enabled: boolean;
  locked: boolean;
  mfaEnabled: boolean;
  roles: string[];
  attributes: Record<string, string>;
  createdAt: number | null;
}

/** Create/update body. password only honoured on create. */
export interface UserWrite {
  username: string;
  /** Optional alternate login identifier; blank/undefined clears it. */
  email?: string;
  password?: string;
  enabled: boolean;
  locked?: boolean;
  attributes?: Record<string, string>;
}

export interface UserApi {
  list(realmId: string): Promise<UserSummary[]>;
  get(realmId: string, userId: string): Promise<UserSummary>;
  create(realmId: string, body: UserWrite): Promise<UserSummary>;
  update(realmId: string, userId: string, body: UserWrite): Promise<UserSummary>;
  resetPassword(realmId: string, userId: string, newPassword: string): Promise<void>;
  remove(realmId: string, userId: string): Promise<void>;
  /** B4: start impersonating the user; returns the landing URL + the identity now in session. */
  impersonate(realmId: string, userId: string): Promise<{ impersonating: string; redirectUrl: string }>;
  /** B1: the user's pending required actions as a CSV string ("" = none). */
  getRequiredActions(realmId: string, userId: string): Promise<string>;
  /** B1: replace the user's pending required actions (CSV; "" clears them all). */
  setRequiredActions(realmId: string, userId: string, requiredActions: string): Promise<void>;
  /** B10: bulk-import users from a CSV or JSON-array payload; existing usernames are skipped. */
  importUsers(realmId: string, payload: string): Promise<UserImportResult>;
}

/** B10: outcome of a bulk import — counts plus per-row failures. */
export interface UserImportResult {
  created: number;
  skipped: number;
  failed: { username: string; error: string }[];
}

/** B1: the required-action keys the console can assign. The user completes these at next login. */
export const REQUIRED_ACTION_OPTIONS: { key: string; label: string }[] = [
  { key: "UPDATE_PASSWORD", label: "Update password" },
  { key: "VERIFY_EMAIL", label: "Verify email" },
  { key: "CONFIGURE_TOTP", label: "Configure OTP (authenticator)" },
  { key: "UPDATE_PROFILE", label: "Update profile" },
  { key: "TERMS_AND_CONDITIONS", label: "Accept terms & conditions" },
];

/** Parse a required-actions CSV into a trimmed, de-duplicated, non-empty list. */
export function parseRequiredActions(csv: string | null | undefined): string[] {
  if (!csv) return [];
  const seen = new Set<string>();
  return csv
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !seen.has(s) && (seen.add(s), true));
}

/** HTTP-backed client for the E8.5 Users admin REST API. */
export function createUserHttpClient(baseUrl = ""): UserApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, userId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/users${userId ? `/${encodeURIComponent(userId)}` : ""}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId) => fetch(url(realmId)).then(json),
    get: (realmId, userId) => fetch(url(realmId, userId)).then(json),
    create: (realmId, body) =>
      fetch(url(realmId), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    update: (realmId, userId, body) =>
      fetch(url(realmId, userId), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    resetPassword: (realmId, userId, newPassword) =>
      fetch(`${url(realmId, userId)}/password`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ newPassword }) }).then(json).then(() => undefined),
    remove: (realmId, userId) => fetch(url(realmId, userId), { method: "DELETE" }).then(json).then(() => undefined),
    impersonate: (realmId, userId) =>
      fetch(`${url(realmId, userId)}/impersonate`, { method: "POST", credentials: "include" }).then(json),
    getRequiredActions: (realmId, userId) =>
      fetch(`${url(realmId, userId)}/required-actions`).then(json).then((r) => (r?.requiredActions ?? "") as string),
    setRequiredActions: (realmId, userId, requiredActions) =>
      fetch(`${url(realmId, userId)}/required-actions`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ requiredActions }) }).then(json).then(() => undefined),
    importUsers: (realmId, payload) =>
      fetch(`${url(realmId)}/import`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ payload }) }).then(json),
  };
}

/** In-memory client for stories/tests. */
export function createUserMemoryClient(seed: UserSummary[] = []): UserApi {
  const store = new Map<string, UserSummary>();
  const actions = new Map<string, string>();
  const key = (realmId: string, userId: string) => `${realmId}|${userId}`;
  let seq = 0;
  seed.forEach((u) => store.set(key(u.realmId, u.userId), u));
  return {
    list: async (realmId) => [...store.values()].filter((u) => u.realmId === realmId),
    get: async (realmId, userId) => {
      const u = store.get(key(realmId, userId));
      if (!u) throw new Error("404 Not Found");
      return u;
    },
    create: async (realmId, body) => {
      const user: UserSummary = {
        realmId, userId: `mem-${++seq}`, username: body.username.toLowerCase(),
        email: body.email?.trim() ? body.email.trim().toLowerCase() : null,
        enabled: body.enabled, locked: body.locked ?? false, mfaEnabled: false,
        roles: [], attributes: body.attributes ?? {}, createdAt: 0,
      };
      store.set(key(realmId, user.userId), user);
      return user;
    },
    update: async (realmId, userId, body) => {
      const prev = store.get(key(realmId, userId));
      if (!prev) throw new Error("404 Not Found");
      const next = { ...prev, email: body.email?.trim() ? body.email.trim().toLowerCase() : null, enabled: body.enabled, locked: body.locked ?? false, attributes: body.attributes ?? {} };
      store.set(key(realmId, userId), next);
      return next;
    },
    resetPassword: async () => undefined,
    remove: async (realmId, userId) => { store.delete(key(realmId, userId)); },
    impersonate: async (_realmId, userId) => ({ impersonating: userId, redirectUrl: "/" }),
    getRequiredActions: async (realmId, userId) => actions.get(key(realmId, userId)) ?? "",
    setRequiredActions: async (realmId, userId, requiredActions) => { actions.set(key(realmId, userId), requiredActions); },
    importUsers: async () => ({ created: 0, skipped: 0, failed: [] }),
  };
}
