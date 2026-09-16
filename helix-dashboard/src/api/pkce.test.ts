import { describe, it, expect } from "vitest";
import { randomString, challengeFromVerifier } from "./pkce";

describe("pkce", () => {
  it("randomString is url-safe and non-empty", () => {
    const s = randomString(32);
    expect(s).toMatch(/^[A-Za-z0-9\-_]+$/);
    expect(s.length).toBeGreaterThan(20);
  });

  it("randomString is different each call", () => {
    expect(randomString(32)).not.toBe(randomString(32));
  });

  it("challengeFromVerifier is the base64url S256 of the verifier (RFC 7636 vector)", async () => {
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = await challengeFromVerifier(verifier);
    expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });
});
