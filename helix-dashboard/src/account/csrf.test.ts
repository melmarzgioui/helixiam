/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { readXsrfToken, csrfHeader } from "./csrf";

describe("account CSRF helper (#322)", () => {
  it("reads the XSRF-TOKEN cookie value, URL-decoded", () => {
    expect(readXsrfToken("foo=1; XSRF-TOKEN=abc%2D123; bar=2")).toBe("abc-123");
    expect(readXsrfToken("XSRF-TOKEN=plain")).toBe("plain");
  });

  it("returns null when the cookie is absent or empty", () => {
    expect(readXsrfToken("foo=1; bar=2")).toBeNull();
    expect(readXsrfToken("")).toBeNull();
    expect(readXsrfToken(null)).toBeNull();
  });

  it("attaches X-XSRF-TOKEN only to unsafe methods that have a token", () => {
    expect(csrfHeader("PUT", "XSRF-TOKEN=tok")).toEqual({ "X-XSRF-TOKEN": "tok" });
    expect(csrfHeader("DELETE", "XSRF-TOKEN=tok")).toEqual({ "X-XSRF-TOKEN": "tok" });
    expect(csrfHeader("POST", "XSRF-TOKEN=tok")).toEqual({ "X-XSRF-TOKEN": "tok" });
  });

  it("attaches nothing for safe methods or when no token is present", () => {
    expect(csrfHeader("GET", "XSRF-TOKEN=tok")).toEqual({});
    expect(csrfHeader(undefined, "XSRF-TOKEN=tok")).toEqual({});
    expect(csrfHeader("PUT", "foo=1")).toEqual({});
  });
});
