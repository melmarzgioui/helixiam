/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Helix IAM Admin SDK (TypeScript) — a small typed wrapper over a few endpoints of the
 * Admin API (OpenAPI group "admin", served under `/admin/realms/{realmId}/**`).
 *
 * This is a demonstration stub: it covers Users, Roles and Organizations, not the full surface.
 * The intent is to show the SDK story; the recommended production path is to GENERATE a client
 * from the live spec at `/v3/api-docs/admin` (see README.md). The types in `./types` and the
 * fetch wrapper below are deliberately framework-free (plain `fetch`) so the same module works
 * in the browser console app and in Node.
 *
 * Usage:
 *   import { createHelixAdminClient } from "./sdk";
 *   const helix = createHelixAdminClient({ baseUrl: "https://iam.example.com" });
 *   const users = await helix.users.list("master");
 */
import type { Organization, OrganizationWrite, Role, User, UserWrite } from "./types";

export type { Organization, OrganizationWrite, Role, User, UserWrite } from "./types";

export interface HelixAdminClientOptions {
  /** Base URL of the IAM server, e.g. "https://iam.example.com". Defaults to same-origin (""). */
  baseUrl?: string;
  /** Optional bearer token; sent as `Authorization: Bearer <token>` on every request. */
  token?: string;
  /** Optional fetch implementation (inject for tests/Node < 18). Defaults to global fetch. */
  fetch?: typeof fetch;
}

/** Thrown for any non-2xx response. Carries the HTTP status and the parsed body when JSON. */
export class HelixApiError extends Error {
  constructor(
    readonly status: number,
    readonly statusText: string,
    readonly body: unknown,
  ) {
    super(`Helix Admin API ${status} ${statusText}`);
    this.name = "HelixApiError";
  }
}

export interface HelixAdminClient {
  users: {
    list(realmId: string): Promise<User[]>;
    get(realmId: string, userId: string): Promise<User>;
    create(realmId: string, body: UserWrite): Promise<User>;
    update(realmId: string, userId: string, body: UserWrite): Promise<User>;
    resetPassword(realmId: string, userId: string, newPassword: string): Promise<void>;
    remove(realmId: string, userId: string): Promise<void>;
  };
  roles: {
    list(realmId: string): Promise<Role[]>;
    create(realmId: string, name: string): Promise<Role>;
    remove(realmId: string, roleId: string): Promise<void>;
    forUser(realmId: string, userId: string): Promise<Role[]>;
    assign(realmId: string, userId: string, roleId: string): Promise<void>;
    unassign(realmId: string, userId: string, roleId: string): Promise<void>;
  };
  organizations: {
    list(realmId: string): Promise<Organization[]>;
    get(realmId: string, orgId: string): Promise<Organization>;
    create(realmId: string, body: OrganizationWrite): Promise<Organization>;
    update(realmId: string, orgId: string, body: OrganizationWrite): Promise<Organization>;
    remove(realmId: string, orgId: string): Promise<void>;
  };
}

export function createHelixAdminClient(options: HelixAdminClientOptions = {}): HelixAdminClient {
  const base = (options.baseUrl ?? "").replace(/\/$/, "");
  const doFetch = options.fetch ?? globalThis.fetch;
  const enc = encodeURIComponent;
  /** All paths below are relative (start with /admin/...); the base URL is prepended in request(). */
  const realmBase = (realmId: string) => `/admin/realms/${enc(realmId)}`;

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const headers: Record<string, string> = { ...(init?.headers as Record<string, string>) };
    if (init?.body) headers["Content-Type"] = "application/json";
    if (options.token) headers["Authorization"] = `Bearer ${options.token}`;
    const res = await doFetch(`${base}${path}`, { ...init, headers });
    if (!res.ok) {
      let body: unknown = null;
      try {
        body = await res.json();
      } catch {
        /* non-JSON error body */
      }
      throw new HelixApiError(res.status, res.statusText, body);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  const usersPath = (realmId: string, userId?: string) =>
    `${realmBase(realmId)}/users${userId ? `/${enc(userId)}` : ""}`;
  const orgsPath = (realmId: string, orgId?: string) =>
    `${realmBase(realmId)}/organizations${orgId ? `/${enc(orgId)}` : ""}`;

  return {
    users: {
      list: (realmId) => request<User[]>(usersPath(realmId)),
      get: (realmId, userId) => request<User>(usersPath(realmId, userId)),
      create: (realmId, body) => request<User>(usersPath(realmId), { method: "POST", body: JSON.stringify(body) }),
      update: (realmId, userId, body) =>
        request<User>(usersPath(realmId, userId), { method: "PUT", body: JSON.stringify(body) }),
      resetPassword: (realmId, userId, newPassword) =>
        request<void>(`${usersPath(realmId, userId)}/password`, {
          method: "PUT",
          body: JSON.stringify({ newPassword }),
        }),
      remove: (realmId, userId) => request<void>(usersPath(realmId, userId), { method: "DELETE" }),
    },
    roles: {
      list: (realmId) => request<Role[]>(`${realmBase(realmId)}/roles`),
      create: (realmId, name) =>
        request<Role>(`${realmBase(realmId)}/roles`, { method: "POST", body: JSON.stringify({ name }) }),
      remove: (realmId, roleId) =>
        request<void>(`${realmBase(realmId)}/roles/${enc(roleId)}`, { method: "DELETE" }),
      forUser: (realmId, userId) => request<Role[]>(`${realmBase(realmId)}/users/${enc(userId)}/roles`),
      assign: (realmId, userId, roleId) =>
        request<void>(`${realmBase(realmId)}/users/${enc(userId)}/roles`, {
          method: "POST",
          body: JSON.stringify({ roleId }),
        }),
      unassign: (realmId, userId, roleId) =>
        request<void>(`${realmBase(realmId)}/users/${enc(userId)}/roles/${enc(roleId)}`, {
          method: "DELETE",
        }),
    },
    organizations: {
      list: (realmId) => request<Organization[]>(orgsPath(realmId)),
      get: (realmId, orgId) => request<Organization>(orgsPath(realmId, orgId)),
      create: (realmId, body) =>
        request<Organization>(orgsPath(realmId), { method: "POST", body: JSON.stringify(body) }),
      update: (realmId, orgId, body) =>
        request<Organization>(orgsPath(realmId, orgId), { method: "PUT", body: JSON.stringify(body) }),
      remove: (realmId, orgId) => request<void>(orgsPath(realmId, orgId), { method: "DELETE" }),
    },
  };
}
