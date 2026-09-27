/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { createMessagingHttpClient, MessagingApiError } from "./messaging";

afterEach(() => vi.unstubAllGlobals());

const stub = (status: number, body: unknown) => {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fn);
  return fn;
};

describe("createMessagingHttpClient", () => {
  it("surfaces the server's {message, fieldErrors} on a 400", async () => {
    stub(400, { message: "The SMTP host is required.", fieldErrors: { "config.host": "The SMTP host is required." } });
    const api = createMessagingHttpClient("");
    const err = await api.saveProvider("acme", { channel: "EMAIL", driver: "SMTP", enabled: true, config: {} }).catch((e) => e);
    expect(err).toBeInstanceOf(MessagingApiError);
    expect(err.status).toBe(400);
    expect(err.message).toBe("The SMTP host is required.");
    expect(err.fieldErrors).toEqual({ "config.host": "The SMTP host is required." });
  });

  it("keeps the status line for a non-JSON error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("oops", { status: 502, statusText: "Bad Gateway" })));
    const err = await createMessagingHttpClient("").listProviders("acme").catch((e) => e);
    expect(err).toBeInstanceOf(MessagingApiError);
    expect(err.message).toBe("502 Bad Gateway");
    expect(err.fieldErrors).toEqual({});
  });

  it("returns the classified email test result", async () => {
    const fn = stub(200, { sent: false, message: "Test email not delivered.", result: "TRANSIENT_FAILURE", reason: "AUTHENTICATION", diagnostic: "HTTP 401" });
    const r = await createMessagingHttpClient("").testProvider("acme", "EMAIL", "me@example.com");
    expect(r).toMatchObject({ result: "TRANSIENT_FAILURE", reason: "AUTHENTICATION", diagnostic: "HTTP 401" });
    expect(fn).toHaveBeenCalledWith("/admin/realms/acme/messaging/providers/EMAIL/test", expect.objectContaining({ method: "POST", body: JSON.stringify({ to: "me@example.com" }) }));
  });
});
