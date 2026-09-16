/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { decodeJwtSid, decodeJwtSub } from "./jwt";

function makeJwt(payload: object): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "RS256" })}.${b64(payload)}.sig`;
}

describe("decodeJwtSid", () => {
  it("returns the sid claim", () => {
    expect(decodeJwtSid(makeJwt({ sid: "abc123", sub: "u" }))).toBe("abc123");
  });
  it("returns null for missing sid, null input, or garbage", () => {
    expect(decodeJwtSid(makeJwt({ sub: "u" }))).toBeNull();
    expect(decodeJwtSid(null)).toBeNull();
    expect(decodeJwtSid("not.a.jwt")).toBeNull();
  });
});

describe("decodeJwtSub", () => {
  it("returns the sub claim", () => {
    expect(decodeJwtSub(makeJwt({ sub: "u-uuid" }))).toBe("u-uuid");
  });
  it("returns null for missing sub or garbage", () => {
    expect(decodeJwtSub(makeJwt({ sid: "x" }))).toBeNull();
    expect(decodeJwtSub(null)).toBeNull();
  });
});
