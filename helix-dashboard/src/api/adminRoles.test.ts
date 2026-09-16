import { describe, expect, it } from "vitest";
import {
  AdminPermission,
  AdminRoleGrants,
  createAdminRoleMemoryClient,
  effectivelyGrants,
  togglePermission,
} from "./adminRoles";

const CATALOG: AdminPermission[] = [
  { key: "realm-admin", label: "Full realm administration" },
  { key: "view-users", label: "View users" },
  { key: "manage-users", label: "Manage users" },
  { key: "manage-clients", label: "Manage clients" },
];

const rows = (): AdminRoleGrants[] => [
  { realmId: "gov", roleId: "r-1", roleName: "user-admin", permissions: ["manage-users"] },
  { realmId: "gov", roleId: "r-2", roleName: "auditor", permissions: [] },
];

describe("togglePermission", () => {
  it("adds a permission when absent and removes when present", () => {
    expect(togglePermission([], "manage-users")).toEqual(["manage-users"]);
    expect(togglePermission(["manage-users", "view-users"], "manage-users")).toEqual(["view-users"]);
  });

  it("is order-stable on add", () => {
    expect(togglePermission(["view-users"], "manage-users")).toEqual(["view-users", "manage-users"]);
  });
});

describe("effectivelyGrants", () => {
  it("matches a directly-held permission", () => {
    expect(effectivelyGrants(["manage-users"], "manage-users")).toBe(true);
    expect(effectivelyGrants(["manage-users"], "manage-clients")).toBe(false);
  });

  it("realm-admin implies every permission", () => {
    expect(effectivelyGrants(["realm-admin"], "manage-clients")).toBe(true);
    expect(effectivelyGrants(["realm-admin"], "view-users")).toBe(true);
  });
});

describe("createAdminRoleMemoryClient", () => {
  it("setPermissions replaces a role's grant set and drops unknown keys", async () => {
    const api = createAdminRoleMemoryClient(CATALOG, rows());
    const saved = await api.setPermissions("gov", "r-1", ["view-users", "bogus-key", "manage-clients"]);
    expect(saved.permissions).toEqual(["view-users", "manage-clients"]);

    const reloaded = await api.roles("gov");
    expect(reloaded.find((r) => r.roleId === "r-1")?.permissions).toEqual(["view-users", "manage-clients"]);
  });

  it("permissions returns the catalogue (matrix columns)", async () => {
    const api = createAdminRoleMemoryClient(CATALOG, rows());
    expect((await api.permissions("gov")).map((p) => p.key)).toContain("manage-users");
  });

  it("clearing all permissions makes a role grant nothing", async () => {
    const api = createAdminRoleMemoryClient(CATALOG, rows());
    const saved = await api.setPermissions("gov", "r-1", []);
    expect(saved.permissions).toEqual([]);
  });
});
