import { describe, it, expect } from "vitest";
import { flowNameError } from "./AuthFlowPage";

describe("flowNameError (named-flow create/rename validation)", () => {
  it("rejects an empty name", () => {
    expect(flowNameError("", [])).toMatch(/give the flow a name/i);
    expect(flowNameError("   ", [])).toMatch(/give the flow a name/i);
  });

  it("rejects names that are not lowercase-hyphen slugs", () => {
    expect(flowNameError("Step Up", [])).toMatch(/lowercase/i);
    expect(flowNameError("UPPER", [])).toMatch(/lowercase/i);
    expect(flowNameError("a", [])).toMatch(/lowercase/i); // too short (min 2)
  });

  it("rejects a name already taken by another flow", () => {
    expect(flowNameError("browser", ["browser", "step-up"])).toMatch(/already exists/i);
  });

  it("allows keeping the same name when renaming (current is excluded from the taken check)", () => {
    expect(flowNameError("step-up", ["browser", "step-up"], "step-up")).toBeNull();
  });

  it("accepts a fresh, valid slug", () => {
    expect(flowNameError("step-up-strong", ["browser"])).toBeNull();
  });
});
