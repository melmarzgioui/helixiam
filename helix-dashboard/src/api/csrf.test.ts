/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { readCookie, csrfHeaders, needsCsrf } from "./csrf";

describe("readCookie", () => {
  it("returns the value of a named cookie", () => {
    expect(readCookie("XSRF-TOKEN", "a=1; XSRF-TOKEN=abc-123; b=2")).toBe("abc-123");
  });
  it("URL-decodes the value", () => {
    expect(readCookie("XSRF-TOKEN", "XSRF-TOKEN=a%2Fb")).toBe("a/b");
  });
  it("returns null when absent or empty", () => {
    expect(readCookie("XSRF-TOKEN", "a=1")).toBeNull();
    expect(readCookie("XSRF-TOKEN", "")).toBeNull();
  });
});

describe("needsCsrf", () => {
  it("is true for mutating methods, false for safe ones", () => {
    for (const m of ["POST", "put", "Delete", "PATCH"]) expect(needsCsrf(m)).toBe(true);
    for (const m of ["GET", "head", "OPTIONS"]) expect(needsCsrf(m)).toBe(false);
  });
});

describe("csrfHeaders", () => {
  it("adds X-XSRF-TOKEN for a mutating request when the cookie is present", () => {
    expect(csrfHeaders("POST", "XSRF-TOKEN=tok-9")).toEqual({ "X-XSRF-TOKEN": "tok-9" });
  });
  it("adds nothing for a safe method", () => {
    expect(csrfHeaders("GET", "XSRF-TOKEN=tok-9")).toEqual({});
  });
  it("adds nothing when the cookie is missing", () => {
    expect(csrfHeaders("POST", "a=1")).toEqual({});
  });
});
