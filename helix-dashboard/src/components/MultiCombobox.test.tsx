import { describe, it, expect } from "vitest";
import { toggleValue, groupComboOptions } from "./MultiCombobox";
import type { ComboOption } from "./Combobox";

describe("toggleValue", () => {
  it("adds a value not present", () => {
    expect(toggleValue(["a"], "b")).toEqual(["a", "b"]);
  });
  it("removes a value already present", () => {
    expect(toggleValue(["a", "b"], "a")).toEqual(["b"]);
  });
});

describe("groupComboOptions", () => {
  const opts: ComboOption[] = [
    { value: "invoices:read", label: "invoices:read", group: "Realm roles" },
    { value: "billing/ledger", label: "ledger", group: "Client: billing" },
    { value: "reports:view", label: "reports:view", group: "Realm roles" },
    { value: "loose", label: "loose" },
  ];
  it("groups options preserving first-seen group order, ungrouped last", () => {
    const groups = groupComboOptions(opts);
    expect(groups.map((g) => g.group)).toEqual(["Realm roles", "Client: billing", ""]);
    expect(groups[0].options.map((o) => o.value)).toEqual(["invoices:read", "reports:view"]);
    expect(groups[1].options.map((o) => o.value)).toEqual(["billing/ledger"]);
    expect(groups[2].options.map((o) => o.value)).toEqual(["loose"]);
  });
});
