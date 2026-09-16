/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { createRealmIoHttpClient } from "./realmIo";

describe("createRealmIoHttpClient", () => {
  it("POSTs a Keycloak export to the realm-scoped /import/keycloak endpoint", async () => {
    const calls: Array<{ url: string; method: string; body?: string }> = [];
    const fakeFetch = (url: string, opts?: RequestInit) => {
      calls.push({ url, method: opts?.method ?? "GET", body: opts?.body as string });
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ realm: "master", slices: { clients: { created: 2, updated: 0, skipped: 0 } } }),
      } as Response);
    };
    // @ts-expect-error inject a fake fetch for the test
    globalThis.fetch = fakeFetch;
    const api = createRealmIoHttpClient("http://localhost:8083");

    const kc = { realm: "shop", clients: [{ clientId: "webapp", protocol: "openid-connect" }] };
    const result = await api.importKeycloak("master", kc);

    expect(calls[0].url).toBe("http://localhost:8083/admin/realms/master/import/keycloak");
    expect(calls[0].method).toBe("POST");
    expect(JSON.parse(calls[0].body!)).toEqual(kc);
    expect(result.slices.clients.created).toBe(2);
  });

  it("forwards onConflict as a query param on import (and omits it when not set)", async () => {
    const calls: string[] = [];
    const fakeFetch = (url: string) => {
      calls.push(url);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ realm: "gov", slices: {} }) } as Response);
    };
    // @ts-expect-error inject a fake fetch for the test
    globalThis.fetch = fakeFetch;
    const api = createRealmIoHttpClient("http://localhost:8083");

    await api.importRealm("gov", { formatVersion: 2 }, "skip");
    expect(calls[0]).toBe("http://localhost:8083/admin/realms/gov/import?onConflict=skip");

    await api.importRealm("gov", { formatVersion: 2 });
    expect(calls[1]).toBe("http://localhost:8083/admin/realms/gov/import");
  });

  it("percent-encodes the realm id in the import path", async () => {
    const calls: string[] = [];
    const fakeFetch = (url: string) => {
      calls.push(url);
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ realm: "a/b", slices: {} }) } as Response);
    };
    // @ts-expect-error inject a fake fetch for the test
    globalThis.fetch = fakeFetch;
    const api = createRealmIoHttpClient("http://localhost:8083");

    await api.importKeycloak("a/b", {});
    expect(calls[0]).toBe("http://localhost:8083/admin/realms/a%2Fb/import/keycloak");
  });
});
