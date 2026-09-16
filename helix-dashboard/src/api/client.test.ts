/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { toRequest, fromConfig, createMemoryClient } from "./client";
import type { IdentityProviderConfig } from "./client";
import type { WizardResult } from "../components/ProviderWizard";

const digidResult: WizardResult = {
  providerType: "digid",
  alias: "digid",
  displayName: "DigiD (CombiConnect)",
  config: { ssoUrl: "https://digid.example/sso", spEntityId: "https://helix.example/sp" },
  mappers: [
    { source: "NameID", target: "username" },
    { source: "email", target: "email" },
  ],
  enabled: true,
};

describe("toRequest", () => {
  it("maps a DigiD wizard result to an eID-scheme request", () => {
    const req = toRequest(digidResult);
    expect(req.alias).toBe("digid");
    expect(req.protocol).toBe("digid"); // eID scheme drives the backend connector
    expect(req.displayName).toBe("DigiD (CombiConnect)");
    expect(req.enabled).toBe(true);
    expect(req.config.ssoUrl).toBe("https://digid.example/sso");
    // mappers serialise to a flat `source=target` list in the config map
    expect(req.config.mappers).toBe("NameID=username,email=email");
  });

  it("serialises custom attribute mappers added in the wizard", () => {
    const req = toRequest({
      ...digidResult,
      mappers: [
        { source: "NameID", target: "username" },
        { source: "urn:oid:2.5.4.10", target: "organization" },
      ],
    });
    expect(req.config.mappers).toBe("NameID=username,urn:oid:2.5.4.10=organization");
  });

  it("omits the mappers key when there are none", () => {
    const req = toRequest({ ...digidResult, mappers: [] });
    expect(req.config.mappers).toBeUndefined();
  });

  it("maps a Google social result to the oidc protocol", () => {
    const req = toRequest({ ...digidResult, providerType: "google", alias: "google", displayName: "Google", config: {} });
    expect(req.protocol).toBe("oidc");
  });

  it("maps a generic SAML result to the saml protocol", () => {
    const req = toRequest({ ...digidResult, providerType: "saml", alias: "corp", displayName: "Corp", config: {} });
    expect(req.protocol).toBe("saml");
  });
});

describe("fromConfig (edit mode round-trip)", () => {
  const stored: IdentityProviderConfig = {
    realmId: "gov",
    alias: "digid",
    protocol: "digid",
    displayName: "DigiD (CombiConnect)",
    enabled: true,
    config: { minimumLoa: "loa3", entityId: "https://helix.example/sp", mappers: "NameID=username,urn:oid:2.5.4.10=organization" },
  };

  it("reverses a stored connection into wizard state", () => {
    const r = fromConfig(stored);
    expect(r.providerType).toBe("digid");
    expect(r.alias).toBe("digid");
    expect(r.displayName).toBe("DigiD (CombiConnect)");
    expect(r.enabled).toBe(true);
    expect(r.config.minimumLoa).toBe("loa3");
    expect(r.config.entityId).toBe("https://helix.example/sp");
    // the serialised mappers key is parsed back out of config, not left in it
    expect(r.config.mappers).toBeUndefined();
    expect(r.mappers).toEqual([
      { source: "NameID", target: "username" },
      { source: "urn:oid:2.5.4.10", target: "organization" },
    ]);
  });

  it("round-trips through toRequest with no loss", () => {
    const back = toRequest(fromConfig(stored));
    expect(back.config.mappers).toBe("NameID=username,urn:oid:2.5.4.10=organization");
    expect(back.config.minimumLoa).toBe("loa3");
    expect(back.protocol).toBe("digid");
  });

  it("handles a connection with no mappers", () => {
    const r = fromConfig({ ...stored, config: { entityId: "x" } });
    expect(r.mappers).toEqual([]);
  });
});

describe("memory client", () => {
  it("creates, lists, gets and deletes connections for a realm", async () => {
    const api = createMemoryClient();

    const created = await api.create("gov", toRequest(digidResult));
    expect(created.realmId).toBe("gov");
    expect(created.alias).toBe("digid");

    expect(await api.list("gov")).toHaveLength(1);
    expect((await api.get("gov", "digid"))?.displayName).toBe("DigiD (CombiConnect)");

    await api.remove("gov", "digid");
    expect(await api.list("gov")).toHaveLength(0);
    expect(await api.get("gov", "digid")).toBeNull();
  });

  it("isolates connections per realm", async () => {
    const api = createMemoryClient();
    await api.create("gov", toRequest(digidResult));
    expect(await api.list("internal")).toHaveLength(0);
  });

  it("upserts on create with the same alias", async () => {
    const api = createMemoryClient();
    await api.create("gov", toRequest(digidResult));
    await api.update("gov", "digid", toRequest({ ...digidResult, displayName: "Renamed" }));
    const list = await api.list("gov");
    expect(list).toHaveLength(1);
    expect(list[0].displayName).toBe("Renamed");
  });
});
