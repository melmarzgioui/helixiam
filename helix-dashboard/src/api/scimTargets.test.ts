import { describe, expect, it } from "vitest";
import { validateScimTarget, createScimTargetMemoryClient, SCIM_EVENT_OPTIONS } from "./scimTargets";

describe("validateScimTarget", () => {
  it("requires an absolute http(s) base URL", () => {
    expect(validateScimTarget({ baseUrl: "" })).toEqual(["baseUrl"]);
    expect(validateScimTarget({ baseUrl: "not-a-url" })).toEqual(["baseUrl"]);
    expect(validateScimTarget({ baseUrl: "ftp://x" })).toEqual(["baseUrl"]);
    expect(validateScimTarget({ baseUrl: "https://sp.example/scim/v2" })).toEqual([]);
  });
});

describe("SCIM_EVENT_OPTIONS", () => {
  it("offers the three user lifecycle events", () => {
    expect(SCIM_EVENT_OPTIONS.map((o) => o.key)).toEqual(["USER_CREATE", "USER_UPDATE", "USER_DELETE"]);
  });
});

describe("createScimTargetMemoryClient", () => {
  it("creates a target with a write-only token (tokenSet, never echoes the token)", async () => {
    const api = createScimTargetMemoryClient();
    const created = await api.create("master", { baseUrl: "https://sp/scim/v2", token: "bearer-1", eventTypes: "USER_CREATE" });
    expect(created.tokenSet).toBe(true);
    expect(created.token).toBeNull();
    expect(await api.list("master")).toHaveLength(1);
  });

  it("preserves tokenSet on edit when no new token is supplied", async () => {
    const api = createScimTargetMemoryClient();
    const created = await api.create("master", { baseUrl: "https://sp/scim/v2", token: "bearer-1" });
    const updated = await api.update("master", created.id, { baseUrl: "https://sp/scim/v3" });
    expect(updated.tokenSet).toBe(true);
    expect(updated.baseUrl).toBe("https://sp/scim/v3");
  });

  it("removes a target", async () => {
    const api = createScimTargetMemoryClient();
    const created = await api.create("master", { baseUrl: "https://sp/scim/v2" });
    await api.remove("master", created.id);
    expect(await api.list("master")).toHaveLength(0);
  });
});
