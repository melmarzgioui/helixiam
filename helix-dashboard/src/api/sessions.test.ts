import { describe, it, expect } from "vitest";
import { buildSessionsQuery } from "./sessions";

describe("buildSessionsQuery", () => {
  it("is empty when no filters", () => {
    expect(buildSessionsQuery({})).toBe("");
  });
  it("encodes q and type", () => {
    expect(buildSessionsQuery({ q: "ci bot", type: "agent" })).toBe("?q=ci+bot&type=agent");
  });
  it("omits blank values", () => {
    expect(buildSessionsQuery({ q: "", type: "user" })).toBe("?type=user");
  });
});
