/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** Helix IAM: fine-grained admin RBAC — the admin-roles / permissions matrix admin API. */

/** One column of the matrix: an admin permission (scope). */
export interface AdminPermission {
  key: string;
  label: string;
}

/** One row of the matrix: a realm role + the permission keys it currently grants. */
export interface AdminRoleGrants {
  realmId: string;
  roleId: string;
  roleName: string;
  permissions: string[];
}

export interface AdminRoleApi {
  permissions(realmId: string): Promise<AdminPermission[]>;
  roles(realmId: string): Promise<AdminRoleGrants[]>;
  setPermissions(realmId: string, roleId: string, permissions: string[]): Promise<AdminRoleGrants>;
}

/** HTTP-backed client for the admin-RBAC REST API ({@code /admin/realms/{realmId}/admin-roles}). */
export function createAdminRoleHttpClient(baseUrl = ""): AdminRoleApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}/admin-roles`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    permissions: (realmId) => fetch(`${root(realmId)}/permissions`).then(json),
    roles: (realmId) => fetch(root(realmId)).then(json),
    setPermissions: (realmId, roleId, permissions) =>
      fetch(`${root(realmId)}/${encodeURIComponent(roleId)}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ permissions }),
      }).then(json),
  };
}

/**
 * Pure matrix toggle helper (TDD'd): returns the next permission set for a role after toggling one permission.
 * Toggling {@code realm-admin} ON yields just {@code [realm-admin]} (it implies everything); toggling any other
 * permission while {@code realm-admin} is held first expands realm-admin away is intentionally NOT done here —
 * the caller decides. Keeps it a deterministic, order-stable set operation.
 */
export function togglePermission(current: string[], key: string): string[] {
  const has = current.includes(key);
  if (has) return current.filter((k) => k !== key);
  return [...current, key];
}

/** True when a role effectively grants {@code key} (directly, or via the realm-admin super-permission). */
export function effectivelyGrants(permissions: string[], key: string): boolean {
  return permissions.includes("realm-admin") || permissions.includes(key);
}

/** In-memory admin-RBAC client for tests/Storybook — no backend. */
export function createAdminRoleMemoryClient(
  catalog: AdminPermission[],
  seed: AdminRoleGrants[],
): AdminRoleApi {
  let rows = seed.map((r) => ({ ...r, permissions: [...r.permissions] }));
  return {
    permissions: async () => catalog,
    roles: async () => rows.map((r) => ({ ...r, permissions: [...r.permissions] })),
    setPermissions: async (_realmId, roleId, permissions) => {
      const valid = new Set(catalog.map((c) => c.key));
      const next = permissions.filter((p) => valid.has(p));
      rows = rows.map((r) => (r.roleId === roleId ? { ...r, permissions: next } : r));
      const saved = rows.find((r) => r.roleId === roleId);
      if (!saved) throw new Error("Unknown role for realm");
      return { ...saved, permissions: [...saved.permissions] };
    },
  };
}
