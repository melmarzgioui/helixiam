/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { Role, createRoleMemoryClient } from "./roles";

const seed = (): Role[] => [
  { realmId: "gov", roleId: "r-admin", name: "admin", system: true, defaultRole: false },
  { realmId: "gov", roleId: "r-user", name: "user", system: true, defaultRole: true },
  { realmId: "gov", roleId: "r-auditor", name: "auditor", system: true, defaultRole: false },
];

describe("createRoleMemoryClient", () => {
  it("list returns the seeded roles carrying system/default flags", async () => {
    const api = createRoleMemoryClient(seed());
    const roles = await api.list("gov");
    expect(roles.find((r) => r.name === "user")?.defaultRole).toBe(true);
    expect(roles.every((r) => r.system)).toBe(true);
  });

  it("setDefault promotes the target and clears the previous default (single default)", async () => {
    const api = createRoleMemoryClient(seed());
    const updated = await api.setDefault("gov", "r-auditor");
    expect(updated.defaultRole).toBe(true);

    const roles = await api.list("gov");
    expect(roles.filter((r) => r.defaultRole).map((r) => r.roleId)).toEqual(["r-auditor"]);
  });

  it("remove refuses to delete a system role", async () => {
    const api = createRoleMemoryClient(seed());
    await expect(api.remove("gov", "r-admin")).rejects.toThrow();
    expect((await api.list("gov")).length).toBe(3);
  });
});
