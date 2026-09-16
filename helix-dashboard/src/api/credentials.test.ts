/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from "vitest";
import {
  CredentialSummary,
  createCredentialMemoryClient,
  groupCredentials,
} from "./credentials";

const cred = (type: string, id: string): CredentialSummary => ({
  type, id, label: `${type}-${id}`, detail: "", createdAt: null, lastUsedAt: null, revocable: true,
});

describe("groupCredentials", () => {
  it("orders groups by FACTOR_KINDS and drops empty families", () => {
    const groups = groupCredentials([cred("recovery-code", "rc"), cred("passkey", "p1"), cred("passkey", "p2")]);
    expect(groups.map((g) => g.kind.type)).toEqual(["passkey", "recovery-code"]);
    expect(groups[0].items).toHaveLength(2);
  });

  it("collects unknown factor types under a trailing Other group", () => {
    const groups = groupCredentials([cred("smoke-signal", "x"), cred("passkey", "p1")]);
    expect(groups.map((g) => g.kind.type)).toEqual(["passkey", "other"]);
  });

  it("returns no groups for an empty list", () => {
    expect(groupCredentials([])).toEqual([]);
  });
});

describe("createCredentialMemoryClient", () => {
  it("revoke removes only the matching (type,id)", async () => {
    const api = createCredentialMemoryClient({ u1: [cred("passkey", "p1"), cred("device", "d1")] });
    await api.revoke("master", "u1", "passkey", "p1");
    const left = await api.list("master", "u1");
    expect(left.map((c) => `${c.type}:${c.id}`)).toEqual(["device:d1"]);
  });

  it("lists empty for an unknown user", async () => {
    const api = createCredentialMemoryClient();
    expect(await api.list("master", "ghost")).toEqual([]);
  });
});
