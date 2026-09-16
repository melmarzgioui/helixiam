/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  validateOrganization,
  organizationLabel,
  parseDomains,
  createOrganizationHttpClient,
} from "./organizations";

describe("validateOrganization", () => {
  it("accepts a normal org", () => {
    expect(validateOrganization({ name: "acme", domains: ["acme.com"] })).toEqual({});
  });
  it("requires a name", () => {
    expect(validateOrganization({ name: "  " }).name).toBeTruthy();
  });
  it("rejects illegal name characters", () => {
    expect(validateOrganization({ name: "bad|name" }).name).toBeTruthy();
  });
  it("rejects an invalid domain", () => {
    expect(validateOrganization({ name: "acme", domains: ["not-a-domain"] }).domains).toBeTruthy();
  });
});

describe("organizationLabel", () => {
  it("prefers the display name when set", () => {
    expect(organizationLabel({ name: "acme", displayName: "Acme Inc" })).toBe("Acme Inc");
  });
  it("falls back to the stable id when display name is null or blank", () => {
    expect(organizationLabel({ name: "acme", displayName: null })).toBe("acme");
    expect(organizationLabel({ name: "acme", displayName: "  " })).toBe("acme");
  });
});

describe("parseDomains", () => {
  it("splits on commas / whitespace / newlines, lowercases and de-dupes", () => {
    expect(parseDomains("Acme.com, acme.io\n acme.com  foo.org")).toEqual(["acme.com", "acme.io", "foo.org"]);
  });
  it("returns an empty list for blank input", () => {
    expect(parseDomains("   ")).toEqual([]);
  });
});

describe("createOrganizationHttpClient", () => {
  it("builds realm-scoped URLs and routes verbs", async () => {
    const calls: Array<{ url: string; method: string; body?: string }> = [];
    // @ts-expect-error inject a fake fetch
    globalThis.fetch = (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET", body: opts?.body as string | undefined });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) } as Response);
    };
    const api = createOrganizationHttpClient("http://localhost:8083");
    await api.list("master");
    await api.create("master", { name: "acme", domains: ["acme.com"] });
    await api.addMember("master", "org-1", "user 2", "admin");
    await api.removeMember("master", "org-1", "user 2");

    expect(calls[0].url).toBe("http://localhost:8083/admin/realms/master/organizations");
    expect(calls[1].method).toBe("POST");
    expect(calls[1].url).toBe("http://localhost:8083/admin/realms/master/organizations");
    expect(JSON.parse(calls[1].body!)).toEqual({ name: "acme", domains: ["acme.com"] });
    expect(calls[2].method).toBe("PUT");
    expect(calls[2].url).toBe("http://localhost:8083/admin/realms/master/organizations/org-1/members/user%202");
    expect(JSON.parse(calls[2].body!)).toEqual({ role: "admin" });
    expect(calls[3].method).toBe("DELETE");
  });
});
