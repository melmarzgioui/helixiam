/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi } from "vitest";
import { validateRealmSettings, isBlankOrHexColor, isBlankOrHttpUrl, createRealmHttpClient, RealmSettings, RealmSettingsWrite } from "./realm";

const base: RealmSettings = {
  realmId: "gov",
  displayName: "Government NL",
  issuer: null,
  accessTokenTtlSeconds: 3600,
  refreshTokenTtlSeconds: 5_184_000,
  reuseRefreshTokens: false,
  requireMfa: false,
  passwordMinLength: 12,
  enabled: true,
  ssoSessionIdleTimeoutSeconds: 1_800,
  ssoSessionMaxLifetimeSeconds: 36_000,
  rememberMe: false,
  rememberMeLifetimeSeconds: 2_592_000,
  lockoutEnabled: false,
  maxLoginFailures: 5,
  lockoutDurationSeconds: 900,
  failureResetSeconds: 900,
  permanentLockout: false,
  passwordRequireUppercase: false,
  passwordRequireLowercase: false,
  passwordRequireDigit: false,
  passwordRequireSpecial: false,
  passwordNotUsername: false,
  passwordHistoryCount: 0,
  breachedPasswordCheck: false,
  captchaProvider: "none",
  captchaSiteKey: null,
  captchaSecretKey: null,
  maxConcurrentSessions: 0,
  concurrentSessionEvictOldest: true,
  riskPolicyEnabled: false,
  riskMediumThreshold: 40,
  riskHighThreshold: 70,
  riskLowAction: "allow",
  riskMediumAction: "step_up",
  riskHighAction: "deny",
  logoUrl: null,
  primaryColor: null,
  backgroundColor: null,
  welcomeText: null,
  customCss: null,
  registrationEnabled: true,
};

describe("validateRealmSettings — auth-hardening", () => {
  it("accepts the default form", () => {
    expect(validateRealmSettings(base)).toEqual([]);
  });

  it("requires a display name", () => {
    expect(validateRealmSettings({ ...base, displayName: "  " })).toContain("displayName");
  });

  it("requires lockout bounds only when lockout is enabled", () => {
    expect(validateRealmSettings({ ...base, lockoutEnabled: false, maxLoginFailures: 0 })).not.toContain("maxLoginFailures");
    const errs = validateRealmSettings({ ...base, lockoutEnabled: true, maxLoginFailures: 0, failureResetSeconds: 0 });
    expect(errs).toContain("maxLoginFailures");
    expect(errs).toContain("failureResetSeconds");
  });

  it("does not require a lockout duration when permanent lockout is on", () => {
    const errs = validateRealmSettings({ ...base, lockoutEnabled: true, permanentLockout: true, lockoutDurationSeconds: 0 });
    expect(errs).not.toContain("lockoutDurationSeconds");
  });

  it("requires a site key when a CAPTCHA provider is selected", () => {
    expect(validateRealmSettings({ ...base, captchaProvider: "turnstile", captchaSiteKey: "" })).toContain("captchaSiteKey");
    expect(validateRealmSettings({ ...base, captchaProvider: "turnstile", captchaSiteKey: "0xABC" })).not.toContain("captchaSiteKey");
  });

  it("rejects a negative password-history count and negative concurrent-session cap", () => {
    expect(validateRealmSettings({ ...base, passwordHistoryCount: -1 })).toContain("passwordHistoryCount");
    expect(validateRealmSettings({ ...base, maxConcurrentSessions: -2 })).toContain("maxConcurrentSessions");
  });

  it("still enforces the pre-existing token/session bounds", () => {
    expect(validateRealmSettings({ ...base, refreshTokenTtlSeconds: 1 })).toContain("refreshShorter");
    expect(validateRealmSettings({ ...base, passwordMinLength: 4 })).toContain("passwordMinLength");
  });
});

describe("validateRealmSettings — B2 branding", () => {
  it("accepts blank branding (= built-in theme)", () => {
    expect(validateRealmSettings({ ...base, logoUrl: "", primaryColor: "", backgroundColor: "" })).toEqual([]);
  });

  it("accepts valid hex colours and an https logo", () => {
    const errs = validateRealmSettings({ ...base, logoUrl: "https://cdn/logo.svg", primaryColor: "#0a7d52", backgroundColor: "#fff" });
    expect(errs).toEqual([]);
  });

  it("rejects a malformed colour", () => {
    expect(validateRealmSettings({ ...base, primaryColor: "green" })).toContain("primaryColor");
    expect(validateRealmSettings({ ...base, backgroundColor: "#12" })).toContain("backgroundColor");
  });

  it("rejects a non-http logo URL", () => {
    expect(validateRealmSettings({ ...base, logoUrl: "javascript:alert(1)" })).toContain("logoUrl");
    expect(validateRealmSettings({ ...base, logoUrl: "ftp://x/y.png" })).toContain("logoUrl");
  });
});

describe("branding field validators", () => {
  it("isBlankOrHexColor", () => {
    expect(isBlankOrHexColor(null)).toBe(true);
    expect(isBlankOrHexColor("")).toBe(true);
    expect(isBlankOrHexColor("#abc")).toBe(true);
    expect(isBlankOrHexColor("#0A7d52")).toBe(true);
    expect(isBlankOrHexColor("0a7d52")).toBe(false);
    expect(isBlankOrHexColor("red")).toBe(false);
  });

  it("isBlankOrHttpUrl", () => {
    expect(isBlankOrHttpUrl(null)).toBe(true);
    expect(isBlankOrHttpUrl("https://x/y")).toBe(true);
    expect(isBlankOrHttpUrl("http://x")).toBe(true);
    expect(isBlankOrHttpUrl("/local")).toBe(false);
  });
});

describe("createRealmHttpClient — self-registration", () => {
  it("sends registrationEnabled in the save payload", async () => {
    const captured: any[] = [];
    const fetchMock = vi.fn(async (_url: string, init?: any) => {
      captured.push(JSON.parse(init.body));
      return { ok: true, json: async () => ({}) } as Response;
    });
    vi.stubGlobal("fetch", fetchMock);

    const api = createRealmHttpClient("");
    const write = { ...base, registrationEnabled: false } as unknown as RealmSettingsWrite;
    await api.save("acme", write);

    expect(captured[0]).toHaveProperty("registrationEnabled", false);
    vi.unstubAllGlobals();
  });
});
