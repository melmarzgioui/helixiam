import { describe, it, expect } from "vitest";
import { PROVIDER_TYPES, findProviderType, loaBandOf, missingConnectionFields } from "./providerCatalog";

describe("eID assurance ladders", () => {
  it("DigiD offers all four DigiD rungs, defaulting to Substantieel (LoA 3)", () => {
    const digid = findProviderType("digid")!;
    expect(digid.loaOptions?.map((o) => o.value)).toEqual(["loa1", "loa2", "loa3", "loa4"]);
    expect(digid.defaultLoaValue).toBe("loa3");
    expect(digid.loaOptions?.map((o) => o.label)).toEqual([
      "Basis (LoA 1)",
      "Midden (LoA 2)",
      "Substantieel (LoA 3)",
      "Hoog (LoA 4)",
    ]);
  });

  it("eHerkenning starts at LoA 2 (no LoA 1 rung exists in the scheme)", () => {
    const eh = findProviderType("eherkenning")!;
    expect(eh.loaOptions?.map((o) => o.value)).toEqual(["loa2", "loa3", "loa4"]);
    expect(eh.defaultLoaValue).toBe("loa3");
  });

  it("eIDAS uses the EU low/substantial/high vocabulary", () => {
    const eidas = findProviderType("eidas")!;
    expect(eidas.loaOptions?.map((o) => o.value)).toEqual(["low", "substantial", "high"]);
    expect(eidas.defaultLoaValue).toBe("substantial");
  });

  it("every eID's default value is one of its own offered rungs", () => {
    for (const t of PROVIDER_TYPES.filter((p) => p.loaOptions)) {
      expect(t.loaOptions!.some((o) => o.value === t.defaultLoaValue)).toBe(true);
    }
  });
});

describe("missingConnectionFields", () => {
  const oidc = findProviderType("oidc")!;
  const saml = findProviderType("saml")!;
  const digid = findProviderType("digid")!;
  const ldap = findProviderType("ldap")!;

  it("flags the required OIDC fields when empty", () => {
    expect(missingConnectionFields(oidc, {}, "a", "A")).toEqual(["issuer", "clientId"]);
    expect(missingConnectionFields(oidc, { issuer: "x", clientId: "y" }, "a", "A")).toEqual([]);
  });

  it("requires SAML metadata via either a URL or an uploaded XML", () => {
    // no metadata at all → flagged under the synthetic "metadata" key
    expect(missingConnectionFields(saml, { entityId: "x" }, "a", "A")).toEqual(["metadata"]);
    // a URL satisfies it
    expect(missingConnectionFields(saml, { entityId: "x", metadataUrl: "u" }, "a", "A")).toEqual([]);
    // an uploaded XML satisfies it too
    expect(missingConnectionFields(saml, { entityId: "x", metadataXml: "<xml/>" }, "a", "A")).toEqual([]);
    // DigiD additionally requires entityId + minimumLoa
    expect(missingConnectionFields(digid, {}, "a", "A")).toEqual(["entityId", "metadata", "minimumLoa"]);
    expect(missingConnectionFields(digid, { entityId: "x", minimumLoa: "loa3", metadataUrl: "u" }, "a", "A")).toEqual([]);
  });

  it("requires the LDAP bind fields", () => {
    expect(missingConnectionFields(ldap, {}, "a", "A")).toEqual(["url", "bindDn"]);
  });

  it("flags a blank alias or display name", () => {
    expect(missingConnectionFields(oidc, { issuer: "x", clientId: "y" }, "  ", "A")).toContain("alias");
    expect(missingConnectionFields(oidc, { issuer: "x", clientId: "y" }, "a", "")).toContain("displayName");
  });
});

describe("loaBandOf", () => {
  it("maps a scheme-specific value to its badge band", () => {
    const digid = findProviderType("digid")!;
    expect(loaBandOf(digid, "loa1")).toBe("low");
    expect(loaBandOf(digid, "loa3")).toBe("substantial");
    expect(loaBandOf(digid, "loa4")).toBe("high");
  });

  it("falls back to the type's default band for an unknown value", () => {
    const digid = findProviderType("digid")!;
    expect(loaBandOf(digid, "nonsense")).toBe(digid.defaultLoa);
  });

  it("returns undefined when no type is given", () => {
    expect(loaBandOf(undefined, "loa3")).toBeUndefined();
  });
});
