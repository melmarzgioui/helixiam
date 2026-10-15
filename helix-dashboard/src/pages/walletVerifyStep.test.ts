/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import type { FlowExecution } from "../api/flows";
import {
  WALLET_VERIFY_ID, firstStepError, flowEngineWarning, setWalletVerifyProvider, stepFieldId, verifyOnlyConnections, walletVerifyStepErrors,
} from "./walletVerifyStep";

const step = (id: string, authenticatorId: string | null, config?: Record<string, string>): FlowExecution =>
  ({ executionId: id, parentId: null, authenticatorId, requirement: "REQUIRED", condition: false, priority: 10, config });

describe("verifyOnlyConnections", () => {
  it("lists the realm's verify-only wallet connections only", () => {
    expect(verifyOnlyConnections([
      { alias: "eudi-verify", protocol: "eudi-wallet", displayName: "Verify", config: { "subject.strategy": "NONE" } },
      { alias: "eudi-wallet", protocol: "eudi-wallet", displayName: "Wallet", config: {} },
      { alias: "digid", protocol: "saml", displayName: "DigiD", config: { "subject.strategy": "NONE" } },
      { alias: "v2", protocol: "OpenID4VP", displayName: "V2", config: { "subject.strategy": " none " } },
    ])).toEqual([{ alias: "eudi-verify", displayName: "Verify" }, { alias: "v2", displayName: "V2" }]);
  });
});

describe("walletVerifyStepErrors", () => {
  it("needs a verify-only connection on every wallet verification step, and ignores other steps", () => {
    const execs = [step("p", "password"), step("w1", WALLET_VERIFY_ID), step("w2", WALLET_VERIFY_ID, { providerAlias: " " }),
      step("w3", WALLET_VERIFY_ID, { providerAlias: "eudi-verify" }), step("w4", WALLET_VERIFY_ID, { providerAlias: "gone" })];
    expect(walletVerifyStepErrors(execs, ["eudi-verify"])).toEqual({
      w1: "authFlow.walletVerify.err.required",
      w2: "authFlow.walletVerify.err.required",
      w4: "authFlow.walletVerify.err.unknown",
    });
  });

  it("only checks presence when the realm's connections are not known", () => {
    expect(walletVerifyStepErrors([step("w", WALLET_VERIFY_ID, { providerAlias: "x" })], undefined)).toEqual({});
    expect(walletVerifyStepErrors([step("p", "password")], [])).toEqual({});
  });
});

describe("setWalletVerifyProvider", () => {
  it("sets the step's providerAlias, keeping its other settings and every other step", () => {
    const execs = [step("p", "password"), step("w", WALLET_VERIFY_ID, { other: "1" })];
    const out = setWalletVerifyProvider(execs, "w", "eudi-verify");
    expect(out[1].config).toEqual({ other: "1", providerAlias: "eudi-verify" });
    expect(out[0]).toBe(execs[0]);
    expect(execs[1].config).toEqual({ other: "1" });
  });
});

describe("flowEngineWarning", () => {
  it("is shown when the engine is off and the flow has a wallet step or the realm has a verify-only connection", () => {
    const wallet = [step("w", WALLET_VERIFY_ID, { providerAlias: "v" })];
    expect(flowEngineWarning(false, wallet, [])).toBe(true);
    expect(flowEngineWarning(false, [step("p", "password")], [{ alias: "v", displayName: "V" }])).toBe(true);
    expect(flowEngineWarning(false, [step("p", "password")], [])).toBe(false);
    expect(flowEngineWarning(true, wallet, [{ alias: "v", displayName: "V" }])).toBe(false);
    expect(flowEngineWarning(undefined, wallet, [])).toBe(false);
  });
});

describe("firstStepError", () => {
  it("is the first erroneous step in flow order (focused when a save is blocked), else null", () => {
    const execs = [step("a", "password"), { ...step("b", WALLET_VERIFY_ID), priority: 30 }, { ...step("c", WALLET_VERIFY_ID), priority: 20 }];
    expect(firstStepError(execs, { b: "x", c: "y" })).toBe("c");
    expect(firstStepError(execs, {})).toBeNull();
    expect(stepFieldId("c")).toBe("wallet-verify-c");
  });
});
