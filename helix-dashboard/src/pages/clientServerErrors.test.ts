/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { AdminApiError } from "../api/adminError";
import { createClientHttpClient } from "../api/clients";
import { splitClientServerErrors } from "./clientServerErrors";

afterEach(() => vi.unstubAllGlobals());

describe("client API errors", () => {
  it("a refused save rejects with the server's message and field errors", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      message: "The JWKS URL must be an https URL.",
      fieldErrors: { jwksUrl: "The JWKS URL must be an https URL." },
    }), { status: 400, statusText: "Bad Request" })));
    const api = createClientHttpClient("");
    const err = await api.update("acme", "id-1", {} as never).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AdminApiError);
    expect((err as AdminApiError).message).toBe("The JWKS URL must be an https URL.");
    expect((err as AdminApiError).fieldErrors).toEqual({ jwksUrl: "The JWKS URL must be an https URL." });
    const created = await api.create("acme", {} as never).catch((e: unknown) => e);
    expect(created).toBeInstanceOf(AdminApiError);
  });

  it("a non-JSON failure keeps the status line", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>", { status: 502, statusText: "Bad Gateway" })));
    const err = await createClientHttpClient("").list("acme").catch((e: unknown) => e);
    expect((err as Error).message).toBe("502 Bad Gateway");
  });
});

describe("splitClientServerErrors", () => {
  it("puts an ID-token algorithm refusal on the credentials tab", () => {
    const split = splitClientServerErrors({ idTokenSignatureAlg: "The realm has no active key for ES256" });
    expect(split.tab).toBe("credentials");
    expect(split.allMapped).toBe(true);
  });

  it("puts form fields on their tab and the rest in the banner", () => {
    const split = splitClientServerErrors({
      jwksUrl: "must be https",
      tokenEndpointAuthMethod: "unknown method",
      redirectUris: "bad redirect",
      clientSecret: "too short",
    });
    expect(split.fields).toEqual({ jwksUrl: "must be https", tokenEndpointAuthMethod: "unknown method",
      redirectUris: "bad redirect" });
    expect(split.other).toEqual(["too short"]);
    expect(split.tab).toBe("keys");
  });

  it("opens the login tab for a login field and no tab without fields", () => {
    expect(splitClientServerErrors({ backchannelLogoutUri: "x" }).tab).toBe("login");
    expect(splitClientServerErrors({ name: "x" }).tab).toBeNull();
    expect(splitClientServerErrors({}).fields).toEqual({});
  });

  it("maps a known jwksUrl error onto its i18n key via the server's stable code", () => {
    const split = splitClientServerErrors(
      { jwksUrl: "The JWKS URL must be an https URL." },
      { jwksUrl: "notHttps" },
    );
    expect(split.fields.jwksUrl).toBe("clientDetail.jwksUrlHttps");

    const split2 = splitClientServerErrors(
      { jwksUrl: "The JWKS URL is not a valid URL." },
      { jwksUrl: "notUrl" },
    );
    expect(split2.fields.jwksUrl).toBe("clientDetail.jwksUrlInvalid");
  });

  it("maps a known tokenEndpointAuthMethod error onto its i18n key via code", () => {
    const split = splitClientServerErrors(
      { tokenEndpointAuthMethod: "Unknown token endpoint auth method (use private_key_jwt, client_secret_basic or none)." },
      { tokenEndpointAuthMethod: "unknown" },
    );
    expect(split.fields.tokenEndpointAuthMethod).toBe("clientDetail.authMethodUnknown");
  });

  it("falls back to matching the server's exact English text when no code is sent", () => {
    const split = splitClientServerErrors({ jwksUrl: "The JWKS URL must be an https URL." });
    expect(split.fields.jwksUrl).toBe("clientDetail.jwksUrlHttps");

    const split2 = splitClientServerErrors({
      tokenEndpointAuthMethod: "Unknown token endpoint auth method (use private_key_jwt, client_secret_basic or none).",
    });
    expect(split2.fields.tokenEndpointAuthMethod).toBe("clientDetail.authMethodUnknown");
  });

  it("passes an unrecognized message (unknown code or unmatched text) through verbatim", () => {
    const split = splitClientServerErrors({ jwksUrl: "Some future server message." }, { jwksUrl: "somethingNew" });
    expect(split.fields.jwksUrl).toBe("Some future server message.");

    const split2 = splitClientServerErrors({ redirectUris: "A totally custom message." });
    expect(split2.fields.redirectUris).toBe("A totally custom message.");
  });

  it("allMapped is true only when every error landed on a known field", () => {
    expect(splitClientServerErrors({ jwksUrl: "x" }).allMapped).toBe(true);
    expect(splitClientServerErrors({ jwksUrl: "x", clientSecret: "y" }).allMapped).toBe(false);
    expect(splitClientServerErrors({}).allMapped).toBe(false);
    expect(splitClientServerErrors({ clientSecret: "y" }).allMapped).toBe(false);
  });
});
