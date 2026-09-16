/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { validateApplication, applicationId, applicationLabel, createApplicationHttpClient } from "./applications";

describe("validateApplication", () => {
  it("accepts a normal name", () => {
    expect(validateApplication({ name: "gov-portal" })).toEqual({});
  });
  it("requires a name", () => {
    expect(validateApplication({ name: "  " }).name).toBeTruthy();
  });
  it("rejects illegal characters", () => {
    expect(validateApplication({ name: "bad|name" }).name).toBeTruthy();
  });
});

describe("applicationId", () => {
  it("matches the backend realmId|name surrogate key", () => {
    expect(applicationId("master", "gov-portal")).toBe("master|gov-portal");
  });
});

describe("applicationLabel", () => {
  it("prefers the display name when set", () => {
    expect(applicationLabel({ name: "gov-portal", displayName: "Gov Portal" })).toBe("Gov Portal");
  });
  it("falls back to the stable id when display name is null or blank", () => {
    expect(applicationLabel({ name: "gov-portal", displayName: null })).toBe("gov-portal");
    expect(applicationLabel({ name: "gov-portal", displayName: "   " })).toBe("gov-portal");
  });
});

describe("createApplicationHttpClient", () => {
  it("builds realm-scoped, name-encoded URLs", async () => {
    const calls: Array<{ url: string; method: string }> = [];
    // @ts-expect-error inject a fake fetch
    globalThis.fetch = (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET" });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) } as Response);
    };
    const api = createApplicationHttpClient("http://localhost:8083");
    await api.list("master");
    await api.remove("master", "gov portal");
    expect(calls[0].url).toBe("http://localhost:8083/admin/realms/master/applications");
    expect(calls[1].method).toBe("DELETE");
    expect(calls[1].url).toBe("http://localhost:8083/admin/realms/master/applications/gov%20portal");
  });
});
