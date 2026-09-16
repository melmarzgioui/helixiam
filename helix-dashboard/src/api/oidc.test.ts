import { describe, it, expect, beforeEach, vi } from "vitest";
import { buildAuthorizeUrl, exchangeCode, buildLogoutUrl } from "./oidc";

class MemStorage implements Storage {
  private m = new Map<string, string>();
  get length() { return this.m.size; }
  clear() { this.m.clear(); }
  getItem(k: string) { return this.m.get(k) ?? null; }
  key(i: number) { return [...this.m.keys()][i] ?? null; }
  removeItem(k: string) { this.m.delete(k); }
  setItem(k: string, v: string) { this.m.set(k, v); }
}

beforeEach(() => {
  globalThis.sessionStorage = new MemStorage();
});

describe("oidc", () => {
  it("buildAuthorizeUrl targets the realm-prefixed authorize endpoint with S256 + state", async () => {
    const url = await buildAuthorizeUrl("master", "http://localhost:8180");
    const u = new URL(url);
    expect(u.pathname).toBe("/realms/master/oauth2/authorize");
    expect(u.searchParams.get("client_id")).toBe("helix-console");
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toBeTruthy();
    expect(u.searchParams.get("redirect_uri")).toBe("http://localhost:8180/console/callback");
    expect(u.searchParams.get("scope")).toBe("openid profile");
    const saved = JSON.parse(sessionStorage.getItem("helix.oidc")!);
    expect(saved.state).toBe(u.searchParams.get("state"));
    expect(saved.verifier).toBeTruthy();
  });

  it("exchangeCode rejects a state mismatch", async () => {
    sessionStorage.setItem("helix.oidc", JSON.stringify({ verifier: "v", state: "expected", nonce: "n" }));
    const params = new URLSearchParams({ code: "abc", state: "WRONG" });
    await expect(exchangeCode("master", params, "http://localhost:8180/console/callback"))
      .rejects.toThrow(/state/i);
  });

  it("exchangeCode posts the token endpoint and returns the id_token", async () => {
    sessionStorage.setItem("helix.oidc", JSON.stringify({ verifier: "v", state: "s", nonce: "n" }));
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true, status: 200, json: async () => ({ id_token: "ID.TOKEN.X", access_token: "AT" }),
    });
    globalThis.fetch = fetchMock;
    const params = new URLSearchParams({ code: "abc", state: "s" });
    const res = await exchangeCode("master", params, "http://localhost:8180/console/callback");
    expect(res.idToken).toBe("ID.TOKEN.X");
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/realms/master/oauth2/token");
    expect(init.method).toBe("POST");
    expect((init.body as URLSearchParams).get("grant_type")).toBe("authorization_code");
    expect((init.body as URLSearchParams).get("code_verifier")).toBe("v");
    expect((init.body as URLSearchParams).get("client_id")).toBe("helix-console");
    // the pending state is cleared after a successful exchange
    expect(sessionStorage.getItem("helix.oidc")).toBeNull();
  });

  it("buildLogoutUrl includes id_token_hint and post_logout_redirect_uri", () => {
    const url = buildLogoutUrl("master", "ID.TOKEN.X", "http://localhost:8180");
    const u = new URL(url);
    expect(u.pathname).toBe("/realms/master/connect/logout");
    expect(u.searchParams.get("id_token_hint")).toBe("ID.TOKEN.X");
    expect(u.searchParams.get("post_logout_redirect_uri")).toBe("http://localhost:8180/");
  });
});
