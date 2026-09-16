import { describe, it, expect } from "vitest";
import { validateWebhook } from "./webhooks";

describe("validateWebhook", () => {
  it("requires an absolute http(s) URL", () => {
    expect(validateWebhook({ url: "https://hooks.example/x" })).toEqual([]);
    expect(validateWebhook({ url: "http://localhost:9099/hook" })).toEqual([]);
    expect(validateWebhook({ url: "" })).toContain("url");
    expect(validateWebhook({ url: "ftp://x/y" })).toContain("url");
    expect(validateWebhook({ url: "/relative" })).toContain("url");
  });
});
