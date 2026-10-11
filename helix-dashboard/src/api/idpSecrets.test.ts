/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { fromIdpResponse, secretWriteConfig, idpSecretKeys } from "./idpSecrets";

describe("fromIdpResponse", () => {
  it("moves the <key>Set flags out of config into secretsSet", () => {
    const c = fromIdpResponse({
      realmId: "r", alias: "up", protocol: "oidc", displayName: "Up", enabled: true,
      config: { clientId: "web", clientSecretSet: true },
    });
    expect(c.config).toEqual({ clientId: "web" });
    expect(c.secretsSet).toEqual({ clientSecret: true });
  });

  it("reads eID key flags, true and false, and leaves unrelated keys alone", () => {
    const c = fromIdpResponse({
      realmId: "r", alias: "digid", protocol: "digid", displayName: "DigiD", enabled: true,
      config: { ssoUrl: "https://idp", spSigningPrivateKeySet: true, spDecryptionPrivateKeySet: false, offsetSet: "x" },
    });
    expect(c.secretsSet).toEqual({ spSigningPrivateKey: true, spDecryptionPrivateKey: false });
    expect(c.config).toEqual({ ssoUrl: "https://idp", offsetSet: "x" });
  });

  it("tolerates a missing config", () => {
    const c = fromIdpResponse({ realmId: "r", alias: "a", protocol: "saml", displayName: "A", enabled: true });
    expect(c.config).toEqual({});
    expect(c.secretsSet).toEqual({});
  });
});

describe("secretWriteConfig", () => {
  it("never sends a blank secret, so the stored one is kept", () => {
    expect(secretWriteConfig({ clientId: "web", clientSecret: "", bindPassword: "  " })).toEqual({ clientId: "web" });
  });

  it("sends a typed secret", () => {
    expect(secretWriteConfig({ clientId: "web", clientSecret: "new" })).toEqual({ clientId: "web", clientSecret: "new" });
  });

  it("keeps blank non-secret values", () => {
    expect(secretWriteConfig({ scopes: "" })).toEqual({ scopes: "" });
  });
});

describe("idpSecretKeys", () => {
  it("names the secret keys per protocol", () => {
    expect(idpSecretKeys("oidc")).toEqual(["clientSecret"]);
    expect(idpSecretKeys("DigiD")).toEqual(["spDecryptionPrivateKey", "spSigningPrivateKey"]);
    expect(idpSecretKeys("ldap")).toContain("bindPassword");
    expect(idpSecretKeys("saml")).toEqual([]);
  });
});
