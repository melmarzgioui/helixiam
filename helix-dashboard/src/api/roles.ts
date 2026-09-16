/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A realm role from the E8.5-S2 Roles admin API. */
export interface Role {
  realmId: string;
  roleId: string;
  name: string;
  /** A curated, protected role (admin/user/auditor) — cannot be deleted. */
  system: boolean;
  /** The realm's default role — auto-assigned to every new user. At most one per realm. */
  defaultRole: boolean;
}

export interface RoleApi {
  list(realmId: string): Promise<Role[]>;
  create(realmId: string, name: string): Promise<Role>;
  remove(realmId: string, roleId: string): Promise<void>;
  /** Designate a role as the realm's default (auto-assigned to new users); clears any prior default. */
  setDefault(realmId: string, roleId: string): Promise<Role>;
  userRoles(realmId: string, userId: string): Promise<Role[]>;
  assign(realmId: string, userId: string, roleId: string): Promise<void>;
  unassign(realmId: string, userId: string, roleId: string): Promise<void>;
}

/** HTTP-backed client for the E8.5-S2 roles admin REST API. */
export function createRoleHttpClient(baseUrl = ""): RoleApi {
  const base = baseUrl.replace(/\/$/, "");
  const realm = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(await errorText(res));
    return res.status === 204 ? null : res.json();
  };
  const ok = async (res: Response) => { if (!res.ok) throw new Error(await errorText(res)); };
  // Admin endpoints reject protected operations with a 400 {message} body — surface that message.
  const errorText = async (res: Response) => {
    try {
      const body = await res.json();
      if (body && typeof body.message === "string") return body.message;
    } catch { /* not JSON */ }
    return `${res.status} ${res.statusText}`;
  };

  return {
    list: (realmId) => fetch(`${realm(realmId)}/roles`).then(json),
    create: (realmId, name) =>
      fetch(`${realm(realmId)}/roles`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) }).then(json),
    remove: (realmId, roleId) => fetch(`${realm(realmId)}/roles/${encodeURIComponent(roleId)}`, { method: "DELETE" }).then(ok),
    setDefault: (realmId, roleId) =>
      fetch(`${realm(realmId)}/roles/${encodeURIComponent(roleId)}/default`, { method: "PUT" }).then(json),
    userRoles: (realmId, userId) => fetch(`${realm(realmId)}/users/${encodeURIComponent(userId)}/roles`).then(json),
    assign: (realmId, userId, roleId) =>
      fetch(`${realm(realmId)}/users/${encodeURIComponent(userId)}/roles`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ roleId }) }).then(ok),
    unassign: (realmId, userId, roleId) =>
      fetch(`${realm(realmId)}/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`, { method: "DELETE" }).then(ok),
  };
}

/** In-memory roles client for tests/Storybook — mirrors the backend's system-role protection + single-default rule. */
export function createRoleMemoryClient(seed: Role[] = []): RoleApi {
  let rows = seed.map((r) => ({ ...r }));
  const inRealm = (realmId: string) => rows.filter((r) => r.realmId === realmId);
  return {
    list: async (realmId) => inRealm(realmId).map((r) => ({ ...r })),
    create: async (realmId, name) => {
      const existing = rows.find((r) => r.realmId === realmId && r.name === name);
      if (existing) return { ...existing };
      const role: Role = { realmId, roleId: `role-${rows.length + 1}`, name, system: false, defaultRole: false };
      rows = [...rows, role];
      return { ...role };
    },
    remove: async (realmId, roleId) => {
      const role = rows.find((r) => r.realmId === realmId && r.roleId === roleId);
      if (!role) throw new Error("Role not found.");
      if (role.system) throw new Error("System roles cannot be deleted.");
      rows = rows.filter((r) => r.roleId !== roleId);
    },
    setDefault: async (realmId, roleId) => {
      const target = rows.find((r) => r.realmId === realmId && r.roleId === roleId);
      if (!target) throw new Error("Role not found.");
      rows = rows.map((r) =>
        r.realmId === realmId ? { ...r, defaultRole: r.roleId === roleId } : r,
      );
      return { ...rows.find((r) => r.roleId === roleId)! };
    },
    userRoles: async () => [],
    assign: async () => {},
    unassign: async () => {},
  };
}
