/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { jwksUrlError } from "./jwksUrl";

describe("jwksUrlError (same rule as the server's JwksUrlPolicy)", () => {
  it("accepts an https URL with a host", () => {
    expect(jwksUrlError("https://keys.example.com/jwks", "PRIVATE_KEY_JWT", false)).toBeNull();
    expect(jwksUrlError("  HTTPS://keys.example.com:8443/.well-known/jwks.json ", "PRIVATE_KEY_JWT", false)).toBeNull();
    expect(jwksUrlError("https://[2001:db8::1]/jwks", "PRIVATE_KEY_JWT", false)).toBeNull();
  });

  it("requires a URL for private_key_jwt only", () => {
    expect(jwksUrlError("", "PRIVATE_KEY_JWT", false)).toBe("required");
    expect(jwksUrlError("   ", "PRIVATE_KEY_JWT", false)).toBe("required");
    expect(jwksUrlError("", "CLIENT_SECRET_BASIC", false)).toBeNull();
    expect(jwksUrlError("", "", false)).toBeNull();
  });

  it("refuses plain http, other schemes and URLs without a host", () => {
    for (const url of ["http://keys.example.com/jwks", "ftp://keys.example.com/jwks", "https:///jwks", "https://my_host/jwks",
      "keys.example.com/jwks", "file:///etc/passwd", "javascript:alert(1)"]) {
      expect(jwksUrlError(url, "PRIVATE_KEY_JWT", false), url).toBe("notHttps");
    }
  });

  it("refuses something that is not a URL", () => {
    expect(jwksUrlError("https://exa mple.com/jwks", "PRIVATE_KEY_JWT", false)).toBe("notUrl");
    expect(jwksUrlError("https://", "PRIVATE_KEY_JWT", false)).toBe("notUrl");
  });

  it("checks a URL even when the method does not need one", () => {
    expect(jwksUrlError("http://keys.example.com/jwks", "CLIENT_SECRET_BASIC", false)).toBe("notHttps");
  });

  it("accepts http to localhost or 127.0.0.1 only in dev", () => {
    for (const url of ["http://localhost:8080/jwks", "http://LOCALHOST/jwks", "http://127.0.0.1:9000/jwks"]) {
      expect(jwksUrlError(url, "PRIVATE_KEY_JWT", true), url).toBeNull();
      expect(jwksUrlError(url, "PRIVATE_KEY_JWT", false), url).toBe("notHttps");
    }
    expect(jwksUrlError("http://keys.internal/jwks", "PRIVATE_KEY_JWT", true)).toBe("notHttps");
    expect(jwksUrlError("http://localhost.evil.com/jwks", "PRIVATE_KEY_JWT", true)).toBe("notHttps");
    expect(jwksUrlError("http://127.0.0.1@evil.com/jwks", "PRIVATE_KEY_JWT", true)).toBe("notHttps");
  });
});
