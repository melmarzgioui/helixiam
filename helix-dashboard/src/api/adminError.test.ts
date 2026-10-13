/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { AdminApiError, adminJson } from "./adminError";

const response = (status: number, body: unknown, statusText = "") =>
  new Response(body === undefined ? null : typeof body === "string" ? body : JSON.stringify(body), { status, statusText });

/** The AdminApiError a call rejects with. */
async function failure(call: Promise<unknown>): Promise<AdminApiError> {
  try {
    await call;
  } catch (e) {
    return e as AdminApiError;
  }
  throw new Error("expected the call to fail");
}

describe("adminJson", () => {
  it("returns the JSON body, or null for 204", async () => {
    expect(await adminJson(response(200, { a: 1 }))).toEqual({ a: 1 });
    expect(await adminJson(response(204, undefined))).toBeNull();
  });

  it("turns a 400 {message, fieldErrors} into an AdminApiError with both", async () => {
    const err = await failure(adminJson(response(400, { message: "Bad host", fieldErrors: { "config.clientIdHost": "Bad host" } })));
    expect(err).toBeInstanceOf(AdminApiError);
    expect(err.message).toBe("Bad host");
    expect(err.status).toBe(400);
    expect(err.fieldErrors).toEqual({ "config.clientIdHost": "Bad host" });
  });

  it("keeps the status line when the error body is not JSON", async () => {
    const err = await failure(adminJson(response(500, "<html>", "Server Error")));
    expect(err).toBeInstanceOf(AdminApiError);
    expect(err.message).toBe("500 Server Error");
    expect(err.fieldErrors).toEqual({});
  });

  it("carries fieldErrorCodes when the server sends stable per-field codes", async () => {
    const err = await failure(adminJson(response(400, {
      message: "The JWKS URL must be an https URL.",
      fieldErrors: { jwksUrl: "The JWKS URL must be an https URL." },
      fieldErrorCodes: { jwksUrl: "notHttps" },
    })));
    expect(err.fieldErrors).toEqual({ jwksUrl: "The JWKS URL must be an https URL." });
    expect(err.fieldErrorCodes).toEqual({ jwksUrl: "notHttps" });
  });

  it("defaults fieldErrorCodes to {} when the server doesn't send any (older/other endpoints)", async () => {
    const err = await failure(adminJson(response(400, { message: "Bad host", fieldErrors: { name: "Bad host" } })));
    expect(err.fieldErrorCodes).toEqual({});
  });
});
