/** A realm's settings from the E8.5-S4 Realm settings admin API. */
export interface RealmSettings {
  realmId: string;
  displayName: string | null;
  issuer: string | null;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  reuseRefreshTokens: boolean;
  requireMfa: boolean;
  passwordMinLength: number;
  enabled: boolean;
  // SSO P3: per-realm SSO session policies (seconds).
  ssoSessionIdleTimeoutSeconds: number;
  ssoSessionMaxLifetimeSeconds: number;
  rememberMe: boolean;
  rememberMeLifetimeSeconds: number;
  // Auth-hardening: account lockout / brute-force protection.
  lockoutEnabled: boolean;
  maxLoginFailures: number;
  lockoutDurationSeconds: number;
  failureResetSeconds: number;
  permanentLockout: boolean;
  // Auth-hardening: password policy.
  passwordRequireUppercase: boolean;
  passwordRequireLowercase: boolean;
  passwordRequireDigit: boolean;
  passwordRequireSpecial: boolean;
  passwordNotUsername: boolean;
  passwordHistoryCount: number;
  // Auth-hardening: breached-password (HIBP).
  breachedPasswordCheck: boolean;
  // Auth-hardening: CAPTCHA. secretKey is write-only — the API never returns it (always null on read).
  captchaProvider: "none" | "turnstile" | "recaptcha";
  captchaSiteKey: string | null;
  captchaSecretKey: string | null;
  // Auth-hardening: concurrent-session limit (0 = unlimited).
  maxConcurrentSessions: number;
  concurrentSessionEvictOldest: boolean;
  // Adaptive risk-based authentication (default OFF).
  riskPolicyEnabled: boolean;
  riskMediumThreshold: number;
  riskHighThreshold: number;
  riskLowAction: "allow" | "step_up" | "deny";
  riskMediumAction: "allow" | "step_up" | "deny";
  riskHighAction: "allow" | "step_up" | "deny";
  // B2: per-realm login theming/branding (all optional; null/blank → built-in KubeDNA theme).
  logoUrl: string | null;
  primaryColor: string | null;
  backgroundColor: string | null;
  welcomeText: string | null;
  customCss: string | null;
  // Per-realm self-registration switch (default true; ANDed with the platform master flag).
  registrationEnabled: boolean;
}

/** The editable subset sent on save (realmId comes from the path). */
export type RealmSettingsWrite = Omit<RealmSettings, "realmId">;

/**
 * Auth-hardening: a pure, unit-testable validator for the Realm Settings form. Returns the set of failing
 * field keys (empty = valid). The page uses this to block save + render inline errors.
 */
export function validateRealmSettings(form: RealmSettings): string[] {
  const missing: string[] = [];
  if (!(form.displayName ?? "").trim()) missing.push("displayName");
  if (!(form.accessTokenTtlSeconds > 0)) missing.push("accessTokenTtlSeconds");
  if (!(form.refreshTokenTtlSeconds > 0)) missing.push("refreshTokenTtlSeconds");
  if (form.refreshTokenTtlSeconds < form.accessTokenTtlSeconds) missing.push("refreshShorter");
  if (!(form.passwordMinLength >= 8 && form.passwordMinLength <= 128)) missing.push("passwordMinLength");
  if (!(form.ssoSessionIdleTimeoutSeconds > 0)) missing.push("ssoSessionIdleTimeoutSeconds");
  if (form.ssoSessionMaxLifetimeSeconds < form.ssoSessionIdleTimeoutSeconds) missing.push("ssoMaxShorter");
  if (form.rememberMe && form.rememberMeLifetimeSeconds < form.ssoSessionMaxLifetimeSeconds) missing.push("rememberShorter");
  // Auth-hardening: lockout bounds (only when enabled).
  if (form.lockoutEnabled) {
    if (!(form.maxLoginFailures >= 1)) missing.push("maxLoginFailures");
    if (!form.permanentLockout && !(form.lockoutDurationSeconds >= 1)) missing.push("lockoutDurationSeconds");
    if (!(form.failureResetSeconds >= 1)) missing.push("failureResetSeconds");
  }
  if (!(form.passwordHistoryCount >= 0)) missing.push("passwordHistoryCount");
  if (!(form.maxConcurrentSessions >= 0)) missing.push("maxConcurrentSessions");
  if (form.captchaProvider !== "none" && !(form.captchaSiteKey ?? "").trim()) missing.push("captchaSiteKey");
  // B2: branding colours, when set, must be valid CSS hex (#rgb / #rrggbb). Logo must be an http(s) URL.
  if (!isBlankOrHexColor(form.primaryColor)) missing.push("primaryColor");
  if (!isBlankOrHexColor(form.backgroundColor)) missing.push("backgroundColor");
  if (!isBlankOrHttpUrl(form.logoUrl)) missing.push("logoUrl");
  return missing;
}

/** B2: a blank colour is fine (= default); a set colour must be a #rgb or #rrggbb hex string. */
export function isBlankOrHexColor(v: string | null): boolean {
  const s = (v ?? "").trim();
  return s === "" || /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(s);
}

/** B2: a blank logo is fine (= default); a set logo must be an absolute http(s) URL. */
export function isBlankOrHttpUrl(v: string | null): boolean {
  const s = (v ?? "").trim();
  return s === "" || /^https?:\/\/.+/.test(s);
}

export interface RealmApi {
  get(realmId: string): Promise<RealmSettings>;
  save(realmId: string, body: RealmSettingsWrite): Promise<RealmSettings>;
}

/** HTTP-backed client for the E8.5-S4 realm settings admin REST API. */
export function createRealmHttpClient(baseUrl = ""): RealmApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}/settings`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  };

  return {
    get: (realmId) => fetch(url(realmId)).then(json),
    save: (realmId, body) =>
      fetch(url(realmId), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
  };
}
