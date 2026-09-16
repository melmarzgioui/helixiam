import { describe, it, expect } from "vitest";
import { eidFacilitatedConfig, isEidScheme, EID_SCHEMES } from "./eidCatalog";

describe("eidFacilitatedConfig", () => {
  it("pre-fills the standard DigiD SAML defaults", () => {
    const c = eidFacilitatedConfig("digid");
    expect(c.binding).toBe("post");
    expect(c.responseBinding).toBe("post"); // modern default; admin switches to "artifact" for classic DigiD
    expect(c.minimumLoa).toBe("loa3");
    // DigiD delivers the BSN in the (encrypted) NameID, so there is no separate subject attribute.
    expect(c.subjectAttribute).toBe("");
  });

  it("pre-fills the standard eHerkenning defaults incl. the KvK entity-concerned attribute", () => {
    const c = eidFacilitatedConfig("eherkenning");
    expect(c.binding).toBe("post");
    expect(c.minimumLoa).toBe("loa3");
    expect(c.subjectAttribute).toMatch(/etoegang/i);
  });

  it("pre-fills the standard eIDAS defaults incl. the EU PersonIdentifier", () => {
    const c = eidFacilitatedConfig("eidas");
    expect(c.binding).toBe("post");
    expect(c.minimumLoa).toBe("substantial");
    expect(c.subjectAttribute).toBe("http://eidas.europa.eu/attributes/naturalperson/PersonIdentifier");
  });

  it("never overwrites operator-specific endpoints (they stay for the admin to supply)", () => {
    const c = eidFacilitatedConfig("digid");
    expect(c.ssoUrl ?? "").toBe("");
    expect(c.idpEntityId ?? "").toBe("");
  });

  it("recognises the three eID schemes and nothing else", () => {
    expect(EID_SCHEMES).toEqual(["digid", "eherkenning", "eidas"]);
    expect(isEidScheme("digid")).toBe(true);
    expect(isEidScheme("eidas")).toBe(true);
    expect(isEidScheme("oidc")).toBe(false);
    expect(isEidScheme("saml")).toBe(false);
  });
});
