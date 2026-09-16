/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { filterComboOptions, comboDisplayLabel, type ComboOption } from "./Combobox";

const OPTS: ComboOption[] = [
  { value: "alice@acme.example", label: "Alice Adams", description: "alice@acme.example" },
  { value: "bob@acme.example", label: "Bob Brown" },
  { value: "carol@corp.example", label: "Carol Clark" },
];

describe("filterComboOptions", () => {
  it("returns all options for an empty or whitespace query", () => {
    expect(filterComboOptions(OPTS, "")).toHaveLength(3);
    expect(filterComboOptions(OPTS, "   ")).toHaveLength(3);
  });
  it("matches on label, case-insensitively", () => {
    expect(filterComboOptions(OPTS, "bob").map((o) => o.value)).toEqual(["bob@acme.example"]);
    expect(filterComboOptions(OPTS, "CAROL").map((o) => o.value)).toEqual(["carol@corp.example"]);
  });
  it("matches on the value/description too", () => {
    expect(filterComboOptions(OPTS, "acme").map((o) => o.value)).toEqual([
      "alice@acme.example",
      "bob@acme.example",
    ]);
  });
  it("returns an empty list when nothing matches", () => {
    expect(filterComboOptions(OPTS, "zzz")).toEqual([]);
  });
});

describe("comboDisplayLabel", () => {
  it("shows the matching option's label", () => {
    expect(comboDisplayLabel("bob@acme.example", OPTS)).toBe("Bob Brown");
  });
  it("falls back to the raw value for a custom entry not in the options", () => {
    expect(comboDisplayLabel("external@vendor.example", OPTS)).toBe("external@vendor.example");
  });
  it("is empty for an empty value", () => {
    expect(comboDisplayLabel("", OPTS)).toBe("");
  });
});
