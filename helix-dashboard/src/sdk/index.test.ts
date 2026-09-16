import { describe, expect, it } from "vitest";
import { createHelixAdminClient, HelixApiError } from "./index";
import type { User } from "./types";

/** A tiny fetch double that records the call and returns a canned response. */
function stubFetch(status: number, json: unknown) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    return {
      ok: status >= 200 && status < 300,
      status,
      statusText: `S${status}`,
      json: async () => json,
    } as Response;
  }) as unknown as typeof fetch;
  return { fn, calls };
}

describe("createHelixAdminClient", () => {
  it("lists users at the realm-scoped path with the bearer token", async () => {
    const seed: User[] = [
      { realmId: "master", userId: "u1", username: "admin", email: null, enabled: true, locked: false, mfaEnabled: false, roles: [], attributes: {}, createdAt: 0 },
    ];
    const { fn, calls } = stubFetch(200, seed);
    const helix = createHelixAdminClient({ baseUrl: "https://iam.example.com/", token: "t0k", fetch: fn });

    const users = await helix.users.list("master");

    expect(users).toEqual(seed);
    expect(calls[0].url).toBe("https://iam.example.com/admin/realms/master/users");
    expect((calls[0].init?.headers as Record<string, string>)["Authorization"]).toBe("Bearer t0k");
  });

  it("POSTs JSON when creating an organization", async () => {
    const { fn, calls } = stubFetch(201, { realmId: "master", orgId: "o1", name: "Acme", displayName: null, domains: [], enabled: true });
    const helix = createHelixAdminClient({ baseUrl: "https://iam.example.com", fetch: fn });

    await helix.organizations.create("master", { name: "Acme" });

    expect(calls[0].url).toBe("https://iam.example.com/admin/realms/master/organizations");
    expect(calls[0].init?.method).toBe("POST");
    expect((calls[0].init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ name: "Acme" });
  });

  it("returns undefined for 204 responses (delete)", async () => {
    const { fn } = stubFetch(204, null);
    const helix = createHelixAdminClient({ fetch: fn });
    await expect(helix.users.remove("master", "u1")).resolves.toBeUndefined();
  });

  it("throws HelixApiError with status + body on non-2xx", async () => {
    const { fn } = stubFetch(400, { message: "bad", fieldErrors: { name: "required" } });
    const helix = createHelixAdminClient({ fetch: fn });
    await expect(helix.organizations.create("master", { name: "" })).rejects.toMatchObject({
      name: "HelixApiError",
      status: 400,
    });
    try {
      await helix.organizations.create("master", { name: "" });
    } catch (e) {
      expect(e).toBeInstanceOf(HelixApiError);
      expect((e as HelixApiError).body).toEqual({ message: "bad", fieldErrors: { name: "required" } });
    }
  });
});
