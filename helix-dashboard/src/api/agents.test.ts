/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { validateAgent, createAgentsHttpClient, agentStats, parseCsv, paginate, ownerIssueCount, ownerStatusById, type Agent } from "./agents";

const DAY = 86_400_000;
function agent(over: Partial<Agent>): Agent {
  return {
    id: "a", realmId: "gov", name: "bot", displayName: null, description: null,
    owner: "alice@acme.example", status: "ACTIVE", authMethod: "SECRET", clientId: null,
    scopes: null, roles: null, enabled: true, createdAt: null, expiresAt: null, lastUsedAt: null,
    ...over,
  };
}

describe("agentStats", () => {
  const now = 1_700_000_000_000;
  it("counts agents by lifecycle status", () => {
    const s = agentStats([
      agent({ status: "ACTIVE" }), agent({ status: "ACTIVE" }),
      agent({ status: "SUSPENDED" }), agent({ status: "REVOKED" }), agent({ status: "EXPIRED" }),
    ], now);
    expect(s.total).toBe(5);
    expect(s.active).toBe(2);
    expect(s.suspended).toBe(1);
    expect(s.revoked).toBe(1);
    expect(s.expired).toBe(1);
  });
  it("flags active agents whose credential expires within 14 days as expiring soon", () => {
    const s = agentStats([
      agent({ status: "ACTIVE", expiresAt: now + 3 * DAY }),   // soon
      agent({ status: "ACTIVE", expiresAt: now + 30 * DAY }),  // far off
      agent({ status: "ACTIVE", expiresAt: null }),            // never expires
      agent({ status: "SUSPENDED", expiresAt: now + 1 * DAY }),// not active → not counted
    ], now);
    expect(s.expiringSoon).toBe(1);
  });
  it("does not count an already-past expiry as expiring soon", () => {
    const s = agentStats([agent({ status: "ACTIVE", expiresAt: now - DAY })], now);
    expect(s.expiringSoon).toBe(0);
  });
});

describe("paginate", () => {
  const items = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  it("returns the requested page slice and total page count", () => {
    const p = paginate(items, 0, 4);
    expect(p.items).toEqual([0, 1, 2, 3]);
    expect(p.page).toBe(0);
    expect(p.pageCount).toBe(3); // ceil(10/4)
    expect(p.total).toBe(10);
  });
  it("returns a partial last page", () => {
    expect(paginate(items, 2, 4).items).toEqual([8, 9]);
  });
  it("clamps an out-of-range page back into bounds", () => {
    const p = paginate(items, 99, 4);
    expect(p.page).toBe(2);
    expect(p.items).toEqual([8, 9]);
  });
  it("reports at least one page for an empty list", () => {
    const p = paginate([], 0, 4);
    expect(p.pageCount).toBe(1);
    expect(p.items).toEqual([]);
  });
});

describe("parseCsv", () => {
  it("splits on commas or whitespace and drops blanks", () => {
    expect(parseCsv("openid invoices:read")).toEqual(["openid", "invoices:read"]);
    expect(parseCsv("a, b ,c")).toEqual(["a", "b", "c"]);
    expect(parseCsv(null)).toEqual([]);
    expect(parseCsv("   ")).toEqual([]);
  });
});

describe("validateAgent", () => {
  it("requires a spaceless name and an owner", () => {
    expect(validateAgent({ name: "billing-bot", owner: "alice@acme.example" })).toEqual([]);
    expect(validateAgent({ name: "", owner: "alice" })).toContain("name");
    expect(validateAgent({ name: "has space", owner: "alice" })).toContain("name");
    expect(validateAgent({ name: "ok", owner: "" })).toContain("owner");
  });
});

describe("createAgentsHttpClient", () => {
  it("routes CRUD + lifecycle to the realm-scoped agents endpoints", async () => {
    const calls: Array<{ url: string; method: string }> = [];
    // @ts-expect-error inject a fake fetch
    globalThis.fetch = (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET" });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) } as Response);
    };
    const api = createAgentsHttpClient("http://localhost:8083");

    await api.list("gov");
    await api.create("gov", { name: "bot", owner: "a@b" });
    await api.suspend("gov", "a-1");
    await api.revoke("gov", "a-1");

    expect(calls[0]).toEqual({ url: "http://localhost:8083/admin/realms/gov/agents", method: "GET" });
    expect(calls[1]).toEqual({ url: "http://localhost:8083/admin/realms/gov/agents", method: "POST" });
    expect(calls[2]).toEqual({ url: "http://localhost:8083/admin/realms/gov/agents/a-1/suspend", method: "POST" });
    expect(calls[3]).toEqual({ url: "http://localhost:8083/admin/realms/gov/agents/a-1/revoke", method: "POST" });
  });
});

describe("owner integrity", () => {
  const reviews = [
    { id: "a", name: "a", owner: "alice", status: "ACTIVE", ownerStatus: "VALID" as const },
    { id: "b", name: "b", owner: "bob", status: "ACTIVE", ownerStatus: "ORPHANED" as const },
    { id: "c", name: "c", owner: "ghost", status: "ACTIVE", ownerStatus: "UNKNOWN" as const },
  ];
  it("counts agents whose owner is not VALID", () => {
    expect(ownerIssueCount(reviews)).toBe(2);
    expect(ownerIssueCount([reviews[0]])).toBe(0);
  });
  it("indexes owner status by agent id", () => {
    expect(ownerStatusById(reviews)).toEqual({ a: "VALID", b: "ORPHANED", c: "UNKNOWN" });
  });
});
