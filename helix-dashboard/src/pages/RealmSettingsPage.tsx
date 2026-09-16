/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Alert } from "../components/Alert";
import { Toast, ToastTone } from "../components/Toast";
import { Spinner } from "../components/Spinner";
import { FormField, Input, Textarea, Select } from "../components/FormField";
import { Switch } from "../components/Switch";
import { CopyRow } from "../components/CopyRow";
import { Tabs } from "../components/Tabs";
import { RealmApi, RealmSettings, RealmSettingsWrite, validateRealmSettings } from "../api/realm";
import { fetchOidcEndpoints, OidcEndpoints } from "../api/endpoints";
import { useT } from "../i18n/LocaleContext";

export interface RealmSettingsPageProps {
  api: RealmApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

/** Render a TTL in seconds as a friendly "1h 30m" / "14d" hint. */
function humanize(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, s && `${s}s`].filter(Boolean).join(" ") || "0s";
}

/** B2: the native colour picker needs a valid hex value; fall back to a default when blank/invalid. */
function hexOr(value: string | null, fallback: string): string {
  const s = (value ?? "").trim();
  return /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(s) ? s : fallback;
}

/**
 * E8.5-S4: the live Realm settings screen — branding, token lifetimes, refresh-token reuse, the
 * realm-wide MFA requirement, password policy and the enabled switch, backed by the realm settings
 * admin API. Reads fall back to platform defaults; saving upserts the realm row.
 */
export function RealmSettingsPage({ api, realmId }: RealmSettingsPageProps) {
  const { t } = useT();
  const [loaded, setLoaded] = React.useState<RealmSettings | null>(null);
  const [form, setForm] = React.useState<RealmSettings | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [attempted, setAttempted] = React.useState(false);
  const [note, setNote] = React.useState<Note | null>(null);
  const [endpoints, setEndpoints] = React.useState<OidcEndpoints | null>(null);
  const [tab, setTab] = React.useState("general");

  const reload = React.useCallback(() => {
    setLoaded(null);
    setForm(null);
    api.get(realmId).then((s) => { setLoaded(s); setForm(s); }).catch((e) => {
      setNote({ tone: "error", title: t("realmSettings.toast.loadError"), message: String(e.message ?? e) });
    });
    fetchOidcEndpoints(realmId).then(setEndpoints).catch(() => undefined);
  }, [api, realmId]);

  React.useEffect(reload, [reload]);

  const set = <K extends keyof RealmSettings>(key: K, value: RealmSettings[K]) =>
    setForm((f) => (f ? { ...f, [key]: value } : f));

  // Validation — required + sane numeric bounds (pure, unit-tested in realm.ts).
  const missing: string[] = form ? validateRealmSettings(form) : [];
  const err = (key: string, msg = t("realmSettings.field.required")) => (attempted && missing.includes(key) ? msg : undefined);

  const dirty = !!(form && loaded) && JSON.stringify(form) !== JSON.stringify(loaded);

  const save = async () => {
    if (!form) return;
    if (missing.length) { setAttempted(true); return; }
    setBusy(true);
    try {
      const write: RealmSettingsWrite = {
        displayName: (form.displayName ?? "").trim() || null,
        issuer: (form.issuer ?? "").trim() || null,
        accessTokenTtlSeconds: form.accessTokenTtlSeconds,
        refreshTokenTtlSeconds: form.refreshTokenTtlSeconds,
        reuseRefreshTokens: form.reuseRefreshTokens,
        requireMfa: form.requireMfa,
        passwordMinLength: form.passwordMinLength,
        enabled: form.enabled,
        ssoSessionIdleTimeoutSeconds: form.ssoSessionIdleTimeoutSeconds,
        ssoSessionMaxLifetimeSeconds: form.ssoSessionMaxLifetimeSeconds,
        rememberMe: form.rememberMe,
        rememberMeLifetimeSeconds: form.rememberMeLifetimeSeconds,
        // Per-realm self-registration switch.
        registrationEnabled: form.registrationEnabled,
        // Auth-hardening: account lockout.
        lockoutEnabled: form.lockoutEnabled,
        maxLoginFailures: form.maxLoginFailures,
        lockoutDurationSeconds: form.lockoutDurationSeconds,
        failureResetSeconds: form.failureResetSeconds,
        permanentLockout: form.permanentLockout,
        // Auth-hardening: password policy.
        passwordRequireUppercase: form.passwordRequireUppercase,
        passwordRequireLowercase: form.passwordRequireLowercase,
        passwordRequireDigit: form.passwordRequireDigit,
        passwordRequireSpecial: form.passwordRequireSpecial,
        passwordNotUsername: form.passwordNotUsername,
        passwordHistoryCount: form.passwordHistoryCount,
        // Auth-hardening: breached-password.
        breachedPasswordCheck: form.breachedPasswordCheck,
        // Auth-hardening: CAPTCHA — only send the secret when the operator entered a new one (blank = keep existing).
        captchaProvider: form.captchaProvider,
        captchaSiteKey: (form.captchaSiteKey ?? "").trim() || null,
        captchaSecretKey: (form.captchaSecretKey ?? "").trim() || null,
        // Auth-hardening: concurrent-session limit.
        maxConcurrentSessions: form.maxConcurrentSessions,
        concurrentSessionEvictOldest: form.concurrentSessionEvictOldest,
        // Adaptive risk-based authentication.
        riskPolicyEnabled: form.riskPolicyEnabled,
        riskMediumThreshold: form.riskMediumThreshold,
        riskHighThreshold: form.riskHighThreshold,
        riskLowAction: form.riskLowAction,
        riskMediumAction: form.riskMediumAction,
        riskHighAction: form.riskHighAction,
        // B2: per-realm login theming/branding (blank → null clears the override).
        logoUrl: (form.logoUrl ?? "").trim() || null,
        primaryColor: (form.primaryColor ?? "").trim() || null,
        backgroundColor: (form.backgroundColor ?? "").trim() || null,
        welcomeText: (form.welcomeText ?? "").trim() || null,
        customCss: (form.customCss ?? "").trim() || null,
      };
      const saved = await api.save(realmId, write);
      setLoaded(saved);
      setForm(saved);
      setAttempted(false);
      setNote({ tone: "success", title: t("realmSettings.toast.saved"), message: t("realmSettings.toast.saved.message", { realmId }) });
    } catch (e: unknown) {
      setNote({ tone: "error", title: t("realmSettings.toast.saveError"), message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Page>
      <PageHeader
        title={t("realmSettings.title")}
        description={t("realmSettings.description", { realmId })}
        actions={
          <>
            {dirty && <span className="hx-unsaved">{t("realmSettings.unsaved")}</span>}
            <Button variant="ghost" onClick={reload} disabled={!dirty || busy}>{t("realmSettings.action.discard")}</Button>
            <Button variant="primary" onClick={save} disabled={busy || !form}>{t("realmSettings.action.save")}</Button>
          </>
        }
      />

      <PageBody>
      {!form ? (
        <div className="hx-loadwrap"><Spinner size={28} label={t("realmSettings.loading")} /></div>
      ) : (
        <>
        <Tabs
          tabs={[
            { id: "general", label: t("realmSettings.tab.general") },
            { id: "tokens", label: t("realmSettings.tab.tokens") },
            { id: "login", label: t("realmSettings.tab.login") },
            { id: "registration", label: t("realmSettings.tab.registration") },
            { id: "branding", label: t("realmSettings.tab.branding") },
            { id: "threat", label: t("realmSettings.tab.threat") },
            { id: "endpoints", label: t("realmSettings.tab.endpoints") },
          ]}
          value={tab}
          onChange={setTab}
        />
        {tab === "endpoints" ? (
          endpoints ? (
            <Section
              title={t("realmSettings.endpoints.title")}
              description={t("realmSettings.endpoints.description")}
            >
              <div className="hx-copylist">
                <CopyRow label={t("realmSettings.endpoints.discovery")} value={endpoints.discovery} />
                <CopyRow label={t("realmSettings.endpoints.issuer")} value={endpoints.issuer} />
                <CopyRow label={t("realmSettings.endpoints.authorization")} value={endpoints.authorization} />
                <CopyRow label={t("realmSettings.endpoints.token")} value={endpoints.token} />
                <CopyRow label={t("realmSettings.endpoints.deviceAuthorization")} value={endpoints.deviceAuthorization} />
                <CopyRow label={t("realmSettings.endpoints.userInfo")} value={endpoints.userInfo} />
                <CopyRow label={t("realmSettings.endpoints.jwks")} value={endpoints.jwks} />
                <CopyRow label={t("realmSettings.endpoints.endSession")} value={endpoints.endSession} />
                <CopyRow label={t("realmSettings.endpoints.introspection")} value={endpoints.introspection} />
                <CopyRow label={t("realmSettings.endpoints.revocation")} value={endpoints.revocation} />
              </div>
            </Section>
          ) : (
            <Alert tone="info">{t("realmSettings.endpoints.unavailable")}</Alert>
          )
        ) : (
        <div className="hx-detailgrid">
          {tab === "general" && (
          <Section title={t("realmSettings.general.title")} description={t("realmSettings.general.description")}>
            <FormField label={t("realmSettings.general.displayName")} required error={err("displayName")} hint={t("realmSettings.general.displayName.hint")}>
              <Input value={form.displayName ?? ""} onChange={(e) => set("displayName", e.target.value)} placeholder="Government NL" />
            </FormField>
            <FormField label={t("realmSettings.general.issuerUrl")}
              hint={(form.issuer ?? "").trim()
                ? t("realmSettings.general.issuerUrl.hint")
                : endpoints
                  ? t("realmSettings.general.issuerUrl.hintDefault", { issuer: endpoints.issuer })
                  : t("realmSettings.general.issuerUrl.hintFull")}>
              <Input value={form.issuer ?? ""} onChange={(e) => set("issuer", e.target.value)}
                placeholder={endpoints?.issuer ?? "https://idp.gov.nl"} />
            </FormField>
            <ToggleRow
              label={t("realmSettings.general.realmEnabled")}
              hint={t("realmSettings.general.realmEnabled.hint")}
              checked={form.enabled}
              onChange={(v) => set("enabled", v)}
            />
          </Section>
          )}
          {tab === "registration" && (
          <Section title={t("realmSettings.registration.title")} description={t("realmSettings.registration.description")}>
            <ToggleRow
              label={t("realmSettings.registration.enabled")}
              hint={t("realmSettings.registration.enabled.hint")}
              checked={form.registrationEnabled}
              onChange={(v) => set("registrationEnabled", v)}
            />
            <Alert tone="info">{t("realmSettings.registration.claimsHint")}</Alert>
          </Section>
          )}
          {tab === "branding" && (
          <Section title={t("realmSettings.branding.title")} description={t("realmSettings.branding.description")}>
            <FormField label={t("realmSettings.branding.logoUrl")} error={err("logoUrl", t("realmSettings.branding.logoUrl.error"))} hint={t("realmSettings.branding.logoUrl.hint")}>
              <Input value={form.logoUrl ?? ""} onChange={(e) => set("logoUrl", e.target.value)} placeholder="https://cdn.example.com/logo.svg" />
            </FormField>
            <FormField label={t("realmSettings.branding.primaryColor")} error={err("primaryColor", t("realmSettings.branding.primaryColor.error"))} hint={t("realmSettings.branding.primaryColor.hint")}>
              <div className="hx-inputrow">
                {/* DS-TODO: needs .hx-colorswatch (native colour-picker input sizing) */}
                <input type="color" aria-label={t("realmSettings.branding.primaryColor.picker")} value={hexOr(form.primaryColor, "#0a7d52")}
                  onChange={(e) => set("primaryColor", e.target.value)} className="hx-colorswatch" />
                <Input value={form.primaryColor ?? ""} onChange={(e) => set("primaryColor", e.target.value)} placeholder="#0a7d52" />
              </div>
            </FormField>
            <FormField label={t("realmSettings.branding.bgColor")} error={err("backgroundColor", t("realmSettings.branding.bgColor.error"))} hint={t("realmSettings.branding.bgColor.hint")}>
              <div className="hx-inputrow">
                {/* DS-TODO: needs .hx-colorswatch (native colour-picker input sizing) */}
                <input type="color" aria-label={t("realmSettings.branding.bgColor.picker")} value={hexOr(form.backgroundColor, "#f5f8f6")}
                  onChange={(e) => set("backgroundColor", e.target.value)} className="hx-colorswatch" />
                <Input value={form.backgroundColor ?? ""} onChange={(e) => set("backgroundColor", e.target.value)} placeholder="#f5f8f6" />
              </div>
            </FormField>
            <FormField label={t("realmSettings.branding.welcomeText")} hint={t("realmSettings.branding.welcomeText.hint")}>
              <Input value={form.welcomeText ?? ""} onChange={(e) => set("welcomeText", e.target.value)} placeholder="Sign in to continue" />
            </FormField>
            <FormField label={t("realmSettings.branding.customCss")} hint={t("realmSettings.branding.customCss.hint")}>
              <Textarea className="hx-mono" value={form.customCss ?? ""} onChange={(e) => set("customCss", e.target.value)} rows={6} spellCheck={false}
                placeholder=".headerBar { justify-content: center; }" />
            </FormField>
          </Section>
          )}
          {tab === "tokens" && (
          <Section title={t("realmSettings.tokens.title")} description={t("realmSettings.tokens.description")}>
            <FormField label={t("realmSettings.tokens.accessTtl")} required error={err("accessTokenTtlSeconds")} hint={t("realmSettings.tokens.accessTtl.hint", { duration: humanize(form.accessTokenTtlSeconds) })}>
              <Input type="number" min={1} value={String(form.accessTokenTtlSeconds)} onChange={(e) => set("accessTokenTtlSeconds", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
            <FormField
              label={t("realmSettings.tokens.refreshTtl")}
              required
              error={err("refreshTokenTtlSeconds") ?? err("refreshShorter", t("realmSettings.tokens.refreshTtl.error"))}
              hint={t("realmSettings.tokens.refreshTtl.hint", { duration: humanize(form.refreshTokenTtlSeconds) })}
            >
              <Input type="number" min={1} value={String(form.refreshTokenTtlSeconds)} onChange={(e) => set("refreshTokenTtlSeconds", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
            <ToggleRow
              label={t("realmSettings.tokens.reuseRefresh")}
              hint={t("realmSettings.tokens.reuseRefresh.hint")}
              checked={form.reuseRefreshTokens}
              onChange={(v) => set("reuseRefreshTokens", v)}
            />
          </Section>
          )}
          {tab === "tokens" && (
          <Section title={t("realmSettings.sso.title")} description={t("realmSettings.sso.description")}>
            <FormField label={t("realmSettings.sso.idleTimeout")} required error={err("ssoSessionIdleTimeoutSeconds")} hint={t("realmSettings.sso.idleTimeout.hint", { duration: humanize(form.ssoSessionIdleTimeoutSeconds) })}>
              <Input type="number" min={1} value={String(form.ssoSessionIdleTimeoutSeconds)} onChange={(e) => set("ssoSessionIdleTimeoutSeconds", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
            <FormField
              label={t("realmSettings.sso.maxLifetime")}
              required
              error={err("ssoMaxShorter", t("realmSettings.sso.maxLifetime.error"))}
              hint={t("realmSettings.sso.maxLifetime.hint", { duration: humanize(form.ssoSessionMaxLifetimeSeconds) })}
            >
              <Input type="number" min={1} value={String(form.ssoSessionMaxLifetimeSeconds)} onChange={(e) => set("ssoSessionMaxLifetimeSeconds", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
            <ToggleRow
              label={t("realmSettings.sso.rememberMe")}
              hint={t("realmSettings.sso.rememberMe.hint")}
              checked={form.rememberMe}
              onChange={(v) => set("rememberMe", v)}
            />
            {form.rememberMe && (
              <FormField
                label={t("realmSettings.sso.rememberMeTtl")}
                error={err("rememberShorter", t("realmSettings.sso.rememberMeTtl.error"))}
                hint={t("realmSettings.sso.rememberMeTtl.hint", { duration: humanize(form.rememberMeLifetimeSeconds) })}
              >
                <Input type="number" min={1} value={String(form.rememberMeLifetimeSeconds)} onChange={(e) => set("rememberMeLifetimeSeconds", Math.floor(Number(e.target.value)) || 0)} />
              </FormField>
            )}
          </Section>
          )}
          {tab === "login" && (
          <Section title={t("realmSettings.security.title")} description={t("realmSettings.security.description")}>
            <ToggleRow
              label={t("realmSettings.security.requireMfa")}
              hint={t("realmSettings.security.requireMfa.hint")}
              checked={form.requireMfa}
              onChange={(v) => set("requireMfa", v)}
            />
            <FormField label={t("realmSettings.security.passwordMinLength")} required error={err("passwordMinLength", t("realmSettings.security.passwordMinLength.error"))} hint={t("realmSettings.security.passwordMinLength.hint")}>
              <Input type="number" min={8} max={128} value={String(form.passwordMinLength)} onChange={(e) => set("passwordMinLength", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
          </Section>
          )}
          {tab === "login" && (
          <Section title={t("realmSettings.password.title")} description={t("realmSettings.password.description")}>
            <ToggleRow label={t("realmSettings.password.requireUppercase")} hint={t("realmSettings.password.requireUppercase.hint")} checked={form.passwordRequireUppercase} onChange={(v) => set("passwordRequireUppercase", v)} />
            <ToggleRow label={t("realmSettings.password.requireLowercase")} hint={t("realmSettings.password.requireLowercase.hint")} checked={form.passwordRequireLowercase} onChange={(v) => set("passwordRequireLowercase", v)} />
            <ToggleRow label={t("realmSettings.password.requireDigit")} hint={t("realmSettings.password.requireDigit.hint")} checked={form.passwordRequireDigit} onChange={(v) => set("passwordRequireDigit", v)} />
            <ToggleRow label={t("realmSettings.password.requireSpecial")} hint={t("realmSettings.password.requireSpecial.hint")} checked={form.passwordRequireSpecial} onChange={(v) => set("passwordRequireSpecial", v)} />
            <ToggleRow label={t("realmSettings.password.notUsername")} hint={t("realmSettings.password.notUsername.hint")} checked={form.passwordNotUsername} onChange={(v) => set("passwordNotUsername", v)} />
            <FormField label={t("realmSettings.password.history")} error={err("passwordHistoryCount", t("realmSettings.password.history.error"))} hint={t("realmSettings.password.history.hint")}>
              <Input type="number" min={0} value={String(form.passwordHistoryCount)} onChange={(e) => set("passwordHistoryCount", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
            <ToggleRow
              label={t("realmSettings.password.breached")}
              hint={t("realmSettings.password.breached.hint")}
              checked={form.breachedPasswordCheck}
              onChange={(v) => set("breachedPasswordCheck", v)}
            />
          </Section>
          )}
          {tab === "threat" && (
          <Section title={t("realmSettings.bruteForce.title")} description={t("realmSettings.bruteForce.description")}>
            <ToggleRow
              label={t("realmSettings.bruteForce.enable")}
              hint={t("realmSettings.bruteForce.enable.hint")}
              checked={form.lockoutEnabled}
              onChange={(v) => set("lockoutEnabled", v)}
            />
            {form.lockoutEnabled && (
              <>
                <FormField label={t("realmSettings.bruteForce.maxFailures")} required error={err("maxLoginFailures", t("realmSettings.bruteForce.maxFailures.error"))} hint={t("realmSettings.bruteForce.maxFailures.hint")}>
                  <Input type="number" min={1} value={String(form.maxLoginFailures)} onChange={(e) => set("maxLoginFailures", Math.floor(Number(e.target.value)) || 0)} />
                </FormField>
                <FormField label={t("realmSettings.bruteForce.failureWindow")} required error={err("failureResetSeconds", t("realmSettings.bruteForce.failureWindow.error"))} hint={t("realmSettings.bruteForce.failureWindow.hint", { duration: humanize(form.failureResetSeconds) })}>
                  <Input type="number" min={1} value={String(form.failureResetSeconds)} onChange={(e) => set("failureResetSeconds", Math.floor(Number(e.target.value)) || 0)} />
                </FormField>
                <ToggleRow
                  label={t("realmSettings.bruteForce.permanent")}
                  hint={t("realmSettings.bruteForce.permanent.hint")}
                  checked={form.permanentLockout}
                  onChange={(v) => set("permanentLockout", v)}
                />
                {!form.permanentLockout && (
                  <FormField label={t("realmSettings.bruteForce.lockoutDuration")} required error={err("lockoutDurationSeconds", t("realmSettings.bruteForce.lockoutDuration.error"))} hint={t("realmSettings.bruteForce.lockoutDuration.hint", { duration: humanize(form.lockoutDurationSeconds) })}>
                    <Input type="number" min={1} value={String(form.lockoutDurationSeconds)} onChange={(e) => set("lockoutDurationSeconds", Math.floor(Number(e.target.value)) || 0)} />
                  </FormField>
                )}
              </>
            )}
          </Section>
          )}
          {tab === "login" && (
          <Section title={t("realmSettings.captcha.title")} description={t("realmSettings.captcha.description")}>
            <FormField label={t("realmSettings.captcha.provider")} hint={t("realmSettings.captcha.provider.hint")}>
              <Select
                value={form.captchaProvider}
                onChange={(v) => set("captchaProvider", v as RealmSettings["captchaProvider"])}
                options={[
                  { value: "none", label: t("realmSettings.captcha.provider.none") },
                  { value: "turnstile", label: t("realmSettings.captcha.provider.turnstile") },
                  { value: "recaptcha", label: t("realmSettings.captcha.provider.recaptcha") },
                ]}
              />
            </FormField>
            {form.captchaProvider !== "none" && (
              <>
                <FormField label={t("realmSettings.captcha.siteKey")} required error={err("captchaSiteKey", t("realmSettings.captcha.siteKey.error"))} hint={t("realmSettings.captcha.siteKey.hint")}>
                  <Input value={form.captchaSiteKey ?? ""} onChange={(e) => set("captchaSiteKey", e.target.value)} placeholder="0x4AAA…" />
                </FormField>
                <FormField label={t("realmSettings.captcha.secretKey")} hint={t("realmSettings.captcha.secretKey.hint")}>
                  <Input type="password" value={form.captchaSecretKey ?? ""} onChange={(e) => set("captchaSecretKey", e.target.value)} placeholder="•••••••• (unchanged)" autoComplete="new-password" />
                </FormField>
              </>
            )}
          </Section>
          )}
          {tab === "tokens" && (
          <Section title={t("realmSettings.concurrentSessions.title")} description={t("realmSettings.concurrentSessions.description")}>
            <FormField label={t("realmSettings.concurrentSessions.max")} error={err("maxConcurrentSessions", t("realmSettings.concurrentSessions.max.error"))} hint={t("realmSettings.concurrentSessions.max.hint")}>
              <Input type="number" min={0} value={String(form.maxConcurrentSessions)} onChange={(e) => set("maxConcurrentSessions", Math.floor(Number(e.target.value)) || 0)} />
            </FormField>
            {form.maxConcurrentSessions > 0 && (
              <ToggleRow
                label={t("realmSettings.concurrentSessions.evict")}
                hint={t("realmSettings.concurrentSessions.evict.hint")}
                checked={form.concurrentSessionEvictOldest}
                onChange={(v) => set("concurrentSessionEvictOldest", v)}
              />
            )}
          </Section>
          )}
          {tab === "threat" && (
          <Section title={t("realmSettings.risk.title")} description={t("realmSettings.risk.description")}>
            <ToggleRow
              label={t("realmSettings.risk.enable")}
              hint={t("realmSettings.risk.enable.hint")}
              checked={form.riskPolicyEnabled}
              onChange={(v) => set("riskPolicyEnabled", v)}
            />
            {form.riskPolicyEnabled && (
              <>
                <FormField label={t("realmSettings.risk.mediumThreshold")} error={err("riskMediumThreshold", t("realmSettings.risk.mediumThreshold.error"))} hint={t("realmSettings.risk.mediumThreshold.hint")}>
                  <Input type="number" min={0} max={100} value={String(form.riskMediumThreshold)} onChange={(e) => set("riskMediumThreshold", Math.floor(Number(e.target.value)) || 0)} />
                </FormField>
                <FormField label={t("realmSettings.risk.highThreshold")} error={err("riskHighThreshold", t("realmSettings.risk.highThreshold.error"))} hint={t("realmSettings.risk.highThreshold.hint")}>
                  <Input type="number" min={0} max={100} value={String(form.riskHighThreshold)} onChange={(e) => set("riskHighThreshold", Math.floor(Number(e.target.value)) || 0)} />
                </FormField>
                {(["riskLowAction", "riskMediumAction", "riskHighAction"] as const).map((k, i) => (
                  <FormField key={k} label={[t("realmSettings.risk.action.low"), t("realmSettings.risk.action.medium"), t("realmSettings.risk.action.high")][i]} hint={i === 0 ? t("realmSettings.risk.action.hint") : undefined}>
                    <Select
                      value={form[k]}
                      onChange={(v) => set(k, v as RealmSettings["riskLowAction"])}
                      options={[
                        { value: "allow", label: t("realmSettings.risk.action.allow") },
                        { value: "step_up", label: t("realmSettings.risk.action.stepUp") },
                        { value: "deny", label: t("realmSettings.risk.action.deny") },
                      ]}
                    />
                  </FormField>
                ))}
              </>
            )}
          </Section>
          )}
        </div>
        )}
        </>
      )}
      </PageBody>

      {note && (
        <div className="hx-toasthost">
          <Toast tone={note.tone} title={note.title} message={note.message} onDismiss={() => setNote(null)} />
        </div>
      )}
    </Page>
  );
}

function ToggleRow({ label, hint, checked, onChange }: { label: string; hint: string; checked: boolean; onChange: (v: boolean) => void }) {
  const id = "sw-" + label.replace(/\W+/g, "-").toLowerCase();
  const labelId = id + "-label";
  return (
    <div className="hx-togglerow">
      <div>
        {/* The switch is a role="switch" button, not a native control, so it's named via aria-labelledby
            (htmlFor doesn't associate a <label> with a button). Clicking the text also toggles it. */}
        <span id={labelId} className="hx-togglerow__label" onClick={() => onChange(!checked)}>{label}</span>
        <span className="hx-field__hint">{hint}</span>
      </div>
      <Switch id={id} ariaLabelledby={labelId} checked={checked} onChange={onChange} />
    </div>
  );
}
