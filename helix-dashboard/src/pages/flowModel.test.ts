import { describe, it, expect } from "vitest";
import { FlowExecution, AuthenticatorCatalogEntry } from "../api/flows";
import { requirementMeta, toJourney, previewScreens, summarizeJourney } from "./flowModel";

const CATALOG: AuthenticatorCatalogEntry[] = [
  { id: "mfa-enabled", displayName: "User has MFA enabled", factorClass: "NONE", levelOfAssurance: 0 },
  { id: "otp", displayName: "One-Time Password (TOTP)", factorClass: "POSSESSION", levelOfAssurance: 2 },
  { id: "push", displayName: "Push Approval", factorClass: "POSSESSION", levelOfAssurance: 6 },
  { id: "webauthn", displayName: "Passkey (WebAuthn)", factorClass: "POSSESSION", levelOfAssurance: 3 },
];

// The seeded master flow: a CONDITIONAL sub-flow holding a condition (mfa-enabled) + offered factors.
const SEEDED: FlowExecution[] = [
  { executionId: "sf", parentId: null, authenticatorId: null, requirement: "CONDITIONAL", condition: false, priority: 10 },
  { executionId: "c1", parentId: "sf", authenticatorId: "mfa-enabled", requirement: "REQUIRED", condition: true, priority: 10 },
  { executionId: "m1", parentId: "sf", authenticatorId: "otp", requirement: "ALTERNATIVE", condition: false, priority: 20 },
  { executionId: "m2", parentId: "sf", authenticatorId: "push", requirement: "ALTERNATIVE", condition: false, priority: 30 },
];

describe("requirementMeta", () => {
  it("maps engine requirements to plain language", () => {
    expect(requirementMeta("REQUIRED").label).toBe("Always");
    expect(requirementMeta("ALTERNATIVE").label).toBe("Any one of");
    expect(requirementMeta("CONDITIONAL").label).toBe("Only when");
    expect(requirementMeta("DISABLED").label).toBe("Off");
  });
  it("falls back gracefully for an unknown value", () => {
    expect(requirementMeta("WAT").label).toBe("WAT");
  });
});

describe("toJourney", () => {
  it("turns a conditional sub-flow into one stage with its condition + offered methods", () => {
    const stages = toJourney(SEEDED, CATALOG);
    expect(stages).toHaveLength(1);
    const s = stages[0];
    expect(s.isGroup).toBe(true);
    expect(s.requirement).toBe("CONDITIONAL");
    expect(s.conditions.map((c) => c.label)).toEqual(["User has MFA enabled"]);
    expect(s.methods.map((m) => m.label)).toEqual(["One-Time Password (TOTP)", "Push Approval"]);
    // alternative children ⇒ the user picks one
    expect(s.selectMode).toBe("ANY");
  });

  it("carries per-execution config through to the journey method", () => {
    const out = toJourney(
      [{ executionId: "idp", parentId: null, authenticatorId: "idp-redirect", requirement: "REQUIRED", condition: false, priority: 10, config: { providerAlias: "digid", mode: "REDIRECT" } }],
      [{ id: "idp-redirect", displayName: "Identity Provider Redirector", factorClass: "NONE", levelOfAssurance: 0 }],
    );
    expect(out[0].methods[0].config).toEqual({ providerAlias: "digid", mode: "REDIRECT" });
  });

  it("uses the backend category to classify grouped children (idp-redirect METHOD despite NONE/LoA 0)", () => {
    // Both children sit in one group; only the backend `category` decides method-vs-condition.
    const out = toJourney(
      [
        { executionId: "grp", parentId: null, authenticatorId: null, requirement: "REQUIRED", condition: false, priority: 10 },
        { executionId: "idp", parentId: "grp", authenticatorId: "idp-redirect", requirement: "ALTERNATIVE", condition: false, priority: 10, config: { providerAlias: "digid", mode: "OPTION" } },
        { executionId: "risk", parentId: "grp", authenticatorId: "risk", requirement: "REQUIRED", condition: false, priority: 20 },
      ],
      [
        { id: "idp-redirect", displayName: "Identity Provider Redirector", factorClass: "NONE", levelOfAssurance: 0, category: "METHOD" },
        { id: "risk", displayName: "Adaptive risk-based authentication", factorClass: "NONE", levelOfAssurance: 0, category: "CONDITION" },
      ],
    );
    const stage = out[0];
    expect(stage.methods.map((m) => m.authenticatorId)).toContain("idp-redirect");
    expect(stage.conditions.map((c) => c.authenticatorId)).toContain("risk");
    expect(stage.conditions.map((c) => c.authenticatorId)).not.toContain("idp-redirect");
  });

  it("orders stages and methods by priority", () => {
    const out = toJourney(
      [
        { executionId: "a", parentId: null, authenticatorId: "webauthn", requirement: "REQUIRED", condition: false, priority: 20 },
        { executionId: "b", parentId: null, authenticatorId: "otp", requirement: "REQUIRED", condition: false, priority: 10 },
      ],
      CATALOG,
    );
    expect(out.map((s) => s.title)).toEqual(["One-Time Password (TOTP)", "Passkey (WebAuthn)"]);
  });

  it("treats a lone authenticator stage as a single-method non-group stage", () => {
    const out = toJourney(
      [{ executionId: "p", parentId: null, authenticatorId: "otp", requirement: "REQUIRED", condition: false, priority: 10 }],
      CATALOG,
    );
    expect(out[0].isGroup).toBe(false);
    expect(out[0].methods).toHaveLength(1);
    expect(out[0].selectMode).toBe("ALL");
  });
});

describe("summarizeJourney", () => {
  it("renders a plain-English one-liner of the compiled flow", () => {
    expect(summarizeJourney(toJourney(SEEDED, CATALOG)))
      .toBe("Email & password → One-Time Password (TOTP) or Push Approval (only when User has MFA enabled)");
  });

  it("joins all-required methods with +", () => {
    const stages = toJourney(
      [
        { executionId: "g", parentId: null, authenticatorId: null, requirement: "REQUIRED", condition: false, priority: 10 },
        { executionId: "a", parentId: "g", authenticatorId: "otp", requirement: "REQUIRED", condition: false, priority: 10 },
        { executionId: "b", parentId: "g", authenticatorId: "webauthn", requirement: "REQUIRED", condition: false, priority: 20 },
      ],
      CATALOG,
    );
    expect(summarizeJourney(stages)).toBe("Email & password → One-Time Password (TOTP) + Passkey (WebAuthn)");
  });

  it("is just the password when there are no extra stages", () => {
    expect(summarizeJourney([])).toBe("Email & password");
  });
});

describe("previewScreens", () => {
  it("renders an optional 'choose how to verify' screen for a conditional any-one-of group", () => {
    const screens = previewScreens(toJourney(SEEDED, CATALOG));
    expect(screens).toHaveLength(1);
    expect(screens[0].optional).toBe(true);
    expect(screens[0].title.toLowerCase()).toContain("verify");
    expect(screens[0].methods).toEqual(["One-Time Password (TOTP)", "Push Approval"]);
  });
});
