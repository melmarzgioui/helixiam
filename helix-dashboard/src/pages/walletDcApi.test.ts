/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  DEFAULT_WALLET_FORM,
  clearEditedErrors,
  firstErrorSection,
  parseOriginList,
  splitWalletServerErrors,
  validateWallet,
  walletConfigFromForm,
  walletFormFromConfig,
  walletWarnings,
  type WalletForm,
  type WalletValidationContext,
} from "./walletProvider";

// The W3C Digital Credentials API settings (dcApi.*) of a wallet connection: stored form, validation mirroring
// WalletConfigValidator.checkDcApi, warnings and server-error mapping.

const ANCHOR = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const valid = (over: Partial<WalletForm> = {}): WalletForm => ({
  ...DEFAULT_WALLET_FORM, accessKeyRef: "software:acme/access-2026", trustAnchors: ANCHOR, ...over,
});
const prod: WalletValidationContext = { devProfile: false };
const dev: WalletValidationContext = { devProfile: true };

describe("dcApi stored settings", () => {
  it("are off, signed and without origins by default", () => {
    const form = walletFormFromConfig({});
    expect(form.dcApiEnabled).toBe(false);
    expect(form.dcApiRequest).toBe("signed");
    expect(form.dcApiExpectedOrigins).toBe("");
  });

  it("read the stored flat map", () => {
    const form = walletFormFromConfig({
      "dcApi.enabled": "TRUE", "dcApi.request": "Unsigned",
      "dcApi.expectedOrigins": "[\"https://login.example.eu\",\"https://id.example.eu\"]",
    });
    expect(form.dcApiEnabled).toBe(true);
    expect(form.dcApiRequest).toBe("unsigned");
    expect(form.dcApiExpectedOrigins).toBe("https://login.example.eu\nhttps://id.example.eu");
  });

  it("write only what differs from the defaults, and round-trip", () => {
    expect(walletConfigFromForm(valid())).not.toHaveProperty("dcApi.enabled");
    expect(walletConfigFromForm(valid())).not.toHaveProperty("dcApi.request");
    expect(walletConfigFromForm(valid())).not.toHaveProperty("dcApi.expectedOrigins");
    const form = valid({ dcApiEnabled: true, dcApiRequest: "unsigned",
      dcApiExpectedOrigins: " https://login.example.eu,\n https://id.example.eu " });
    const stored = walletConfigFromForm(form);
    expect(stored["dcApi.enabled"]).toBe("true");
    expect(stored["dcApi.request"]).toBe("unsigned");
    expect(stored["dcApi.expectedOrigins"]).toBe("[\"https://login.example.eu\",\"https://id.example.eu\"]");
    expect(walletConfigFromForm(walletFormFromConfig(stored))).toEqual(stored);
  });

  it("are form keys: switching the API off drops stale stored values", () => {
    const stored = walletConfigFromForm(valid(), { "dcApi.enabled": "true", "dcApi.request": "unsigned" });
    expect(stored).not.toHaveProperty("dcApi.enabled");
    expect(stored).not.toHaveProperty("dcApi.request");
  });
});

describe("parseOriginList", () => {
  it("splits on commas, spaces and new lines", () => {
    expect(parseOriginList(" https://a.example ,https://b.example\n\nhttps://c.example:8443 ")).toEqual([
      "https://a.example", "https://b.example", "https://c.example:8443"]);
  });
});

describe("validateWallet: dcApi.expectedOrigins", () => {
  const errorFor = (origins: string, ctx = prod) =>
    validateWallet(valid({ dcApiEnabled: true, dcApiExpectedOrigins: origins }), ctx)["dcApi.expectedOrigins"];

  it("accepts serialised https origins, and blank (the server's own origin)", () => {
    expect(errorFor("")).toBeUndefined();
    expect(errorFor("https://login.example.eu\nhttps://id.example.eu:8443")).toBeUndefined();
  });

  it.each([
    "https://login.example.eu/", "https://login.example.eu/path", "https://Login.example.eu", "HTTPS://x.example",
    "https://login.example.eu:443", "https://u@login.example.eu", "https://x.example?q=1", "https://x.example#f",
    "login.example.eu", "origin:https://x.example", "ftp://x.example", "http://login.example.eu",
  ])("refuses %s", (origin) => {
    expect(errorFor(origin)).toBe("wallet.err.dcApiOrigin");
  });

  it("allows plain http only for localhost in the dev profile", () => {
    expect(errorFor("http://localhost:9000")).toBe("wallet.err.dcApiOrigin");
    expect(errorFor("http://localhost:9000", dev)).toBeUndefined();
    expect(errorFor("http://evil.example", dev)).toBe("wallet.err.dcApiOrigin");
  });

  it("refuses repeats and more than ten", () => {
    expect(errorFor("https://a.example https://a.example")).toBe("wallet.err.dcApiOriginRepeated");
    const eleven = Array.from({ length: 11 }, (_, i) => `https://h${i}.example`).join("\n");
    expect(errorFor(eleven)).toBe("wallet.err.dcApiOriginsTooMany");
  });

  it("checks the list even while the API is off (a stored list must stay usable)", () => {
    expect(validateWallet(valid({ dcApiEnabled: false, dcApiExpectedOrigins: "nope" }), prod)["dcApi.expectedOrigins"])
      .toBe("wallet.err.dcApiOrigin");
  });
});

describe("dcApi warnings, errors and sections", () => {
  it("warns about unsigned requests (no verifier authentication beyond the web origin)", () => {
    expect(walletWarnings(valid({ dcApiEnabled: true, dcApiRequest: "unsigned" }))).toContain("dcApiUnsigned");
    expect(walletWarnings(valid({ dcApiEnabled: true, dcApiRequest: "signed" }))).not.toContain("dcApiUnsigned");
    expect(walletWarnings(valid({ dcApiEnabled: false, dcApiRequest: "unsigned" }))).not.toContain("dcApiUnsigned");
  });

  it("maps the server's dcApi field errors onto the policies section", () => {
    const { fields, other } = splitWalletServerErrors({
      "config.dcApi.expectedOrigins": "https://x.example is not a host this server answers for",
      "config.dcApi.request": "dcApi.request must be one of [signed, unsigned]",
    });
    expect(other).toEqual([]);
    expect(Object.keys(fields)).toEqual(["dcApi.expectedOrigins", "dcApi.request"]);
    expect(firstErrorSection(fields)).toBe("policies");
  });

  it("editing the origins clears their server error", () => {
    expect(clearEditedErrors({ "dcApi.expectedOrigins": "bad" }, { dcApiExpectedOrigins: "https://a.example" }))
      .toEqual({});
    expect(clearEditedErrors({ "dcApi.request": "bad" }, { dcApiRequest: "unsigned" })).toEqual({});
  });
});
