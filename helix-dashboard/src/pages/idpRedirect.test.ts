import { describe, it, expect } from "vitest";
import { FlowExecution } from "../api/flows";
import { readIdpRedirect, upsertIdpRedirect, MODE_REDIRECT, MODE_OPTION, MODE_LOCAL_ONLY } from "./idpRedirect";

const otp: FlowExecution = { executionId: "otp", parentId: null, authenticatorId: "otp", requirement: "REQUIRED", condition: false, priority: 20 };
const step = (config: Record<string, string>): FlowExecution => ({ executionId: "idp", parentId: null, authenticatorId: "idp-redirect", requirement: "REQUIRED", condition: false, priority: 5, config });

describe("idpRedirect helpers", () => {
  it("readIdpRedirect returns null when there is no idp-redirect step", () => {
    expect(readIdpRedirect([otp])).toBeNull();
  });

  it("reads a REDIRECT step (single provider)", () => {
    expect(readIdpRedirect([step({ providerAlias: "digid", mode: "REDIRECT" }), otp]))
      .toEqual({ mode: MODE_REDIRECT, aliases: ["digid"] });
  });

  it("defaults an unset mode with a single alias to REDIRECT", () => {
    expect(readIdpRedirect([step({ providerAlias: "digid" })])).toEqual({ mode: MODE_REDIRECT, aliases: ["digid"] });
  });

  it("reads an OPTION step with multiple providers", () => {
    expect(readIdpRedirect([step({ mode: "OPTION", providerAliases: "digid,eidas,eherkenning" })]))
      .toEqual({ mode: MODE_OPTION, aliases: ["digid", "eidas", "eherkenning"] });
  });

  it("reads a LOCAL_ONLY step", () => {
    expect(readIdpRedirect([step({ mode: "LOCAL_ONLY" })])).toEqual({ mode: MODE_LOCAL_ONLY, aliases: [] });
  });

  it("upsertIdpRedirect writes a REDIRECT step that runs first and preserves other steps", () => {
    const out = upsertIdpRedirect([otp], MODE_REDIRECT, ["digid"]);
    expect(out).toHaveLength(2);
    expect(out[0].authenticatorId).toBe("idp-redirect");
    expect(out[0].config).toEqual({ mode: "REDIRECT", providerAlias: "digid" });
    expect(out[0].priority).toBeLessThan(otp.priority);
    expect(out.some((e) => e.executionId === "otp")).toBe(true);
  });

  it("upsertIdpRedirect writes an OPTION step with the provider list", () => {
    const out = upsertIdpRedirect([otp], MODE_OPTION, ["digid", "eidas"]);
    expect(out[0].config).toEqual({ mode: "OPTION", providerAliases: "digid,eidas" });
  });

  it("upsertIdpRedirect writes a LOCAL_ONLY step even with no aliases", () => {
    const out = upsertIdpRedirect([otp], MODE_LOCAL_ONLY, []);
    expect(out[0].config).toEqual({ mode: "LOCAL_ONLY" });
  });

  it("upsertIdpRedirect replaces any existing idp-redirect step (no duplicates)", () => {
    const first = upsertIdpRedirect([otp], MODE_REDIRECT, ["digid"]);
    const second = upsertIdpRedirect(first, MODE_OPTION, ["eherkenning"]);
    expect(second.filter((e) => e.authenticatorId === "idp-redirect")).toHaveLength(1);
    expect(second[0].config).toEqual({ mode: "OPTION", providerAliases: "eherkenning" });
  });

  it("upsertIdpRedirect with no providers (and not local-only) removes the step", () => {
    const withIdp = upsertIdpRedirect([otp], MODE_REDIRECT, ["digid"]);
    const cleared = upsertIdpRedirect(withIdp, MODE_OPTION, []);
    expect(cleared.some((e) => e.authenticatorId === "idp-redirect")).toBe(false);
    expect(cleared).toHaveLength(1);
  });
});
