/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { parseRequiredActions, REQUIRED_ACTION_OPTIONS } from "./users";

describe("parseRequiredActions", () => {
  it("returns an empty list for null/blank input", () => {
    expect(parseRequiredActions(null)).toEqual([]);
    expect(parseRequiredActions(undefined)).toEqual([]);
    expect(parseRequiredActions("")).toEqual([]);
    expect(parseRequiredActions("  , ,")).toEqual([]);
  });

  it("splits a CSV and trims whitespace", () => {
    expect(parseRequiredActions("UPDATE_PASSWORD, VERIFY_EMAIL")).toEqual([
      "UPDATE_PASSWORD",
      "VERIFY_EMAIL",
    ]);
  });

  it("drops empty segments and de-duplicates while preserving order", () => {
    expect(parseRequiredActions("UPDATE_PASSWORD,,UPDATE_PASSWORD,CONFIGURE_TOTP")).toEqual([
      "UPDATE_PASSWORD",
      "CONFIGURE_TOTP",
    ]);
  });
});

describe("REQUIRED_ACTION_OPTIONS", () => {
  it("offers UPDATE_PASSWORD as a selectable action with a human label", () => {
    const updatePassword = REQUIRED_ACTION_OPTIONS.find((o) => o.key === "UPDATE_PASSWORD");
    expect(updatePassword?.label).toBe("Update password");
  });
});
