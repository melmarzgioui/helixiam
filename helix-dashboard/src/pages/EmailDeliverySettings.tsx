/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Section } from "../components/Page";
import { Alert } from "../components/Alert";
import { Badge } from "../components/Badge";
import { Button } from "../components/Button";
import { FormField, Input, Textarea } from "../components/FormField";
import { RadioCard } from "../components/Choice";
import { Switch } from "../components/Switch";
import { MessagingApi, MessagingApiError, MessagingProvider } from "../api/messaging";
import { useT } from "../i18n/LocaleContext";
import {
  EMAIL_DEFAULTS,
  EMAIL_DRIVERS,
  EmailDriver,
  EmailForm,
  FieldErrors,
  TLS_MODES,
  TestResultView,
  TlsMode,
  defaultPort,
  describeTestResult,
  formFromProvider,
  initialEmailDriver,
  isDirty,
  otherEnabledEmailDrivers,
  resolveTlsMode,
  setPort,
  setTlsMode,
  splitServerErrors,
  toWrite,
  validateEmailForm,
  validateTestRecipient,
} from "./emailSettings";

export interface EmailDeliverySettingsProps {
  api: MessagingApi;
  realmId: string;
  providers: MessagingProvider[];
  /** Reload the provider list after a change (without unmounting this form). */
  onChanged: () => Promise<void>;
  onSaved: () => void;
}

type Drafts = Partial<Record<EmailDriver, EmailForm>>;

const findEmail = (providers: MessagingProvider[], driver: EmailDriver) =>
  providers.find((p) => p.channel === "EMAIL" && p.driver === driver);

/**
 * Email tab of Notifications: choose how this realm sends email (SMTP, Cloudflare Email Service, an HTTP relay or
 * the dev log), configure it with write-only secrets, and send a classified test email.
 *
 * Extension point: realm-wide email policy (stage 2: a per-realm send rate cap) goes in its own Section after the
 * provider sections, with its own model and validator in emailSettings.ts.
 */
export function EmailDeliverySettings({ api, realmId, providers, onChanged, onSaved }: EmailDeliverySettingsProps) {
  const { t } = useT();
  const [driver, setDriver] = React.useState<EmailDriver>(() => initialEmailDriver(providers));
  const [baselines, setBaselines] = React.useState<Drafts>({});
  const [drafts, setDrafts] = React.useState<Drafts>({});
  const [errors, setErrors] = React.useState<FieldErrors>({});
  const [serverErrors, setServerErrors] = React.useState<Record<string, string>>({});
  const [bannerErrors, setBannerErrors] = React.useState<string[]>([]);
  const [saving, setSaving] = React.useState(false);
  const [turningOff, setTurningOff] = React.useState<string | null>(null);

  const existing = findEmail(providers, driver);
  const anyEnabled = providers.some((p) => p.channel === "EMAIL" && p.enabled);
  const baseline = baselines[driver] ?? formFromProvider(driver, existing, carryFrom(drafts, providers), !anyEnabled);
  const form = drafts[driver] ?? baseline;
  const dirty = !existing || isDirty(form, baseline);
  const others = otherEnabledEmailDrivers(providers, driver);

  const update = (next: EmailForm) => {
    setDrafts((d) => ({ ...d, [driver]: next }));
    if (Object.keys(errors).length || Object.keys(serverErrors).length) {
      // Re-check live once the user has tried to save, so fixed fields clear their error.
      setErrors(Object.keys(errors).length ? validateEmailForm(next) : {});
      setServerErrors({});
    }
  };
  const setConfig = (key: string, value: string) => update({ ...form, config: { ...form.config, [key]: value } });

  const chooseDriver = (d: EmailDriver) => {
    if (d === driver) return;
    setDrafts((prev) => (prev[d] ? prev : { ...prev, [d]: formFromProvider(d, findEmail(providers, d), carryFrom({ ...prev, [driver]: form }, providers), !anyEnabled) }));
    setDriver(d);
    setErrors({});
    setServerErrors({});
    setBannerErrors([]);
  };

  const fieldError = (key: string) => errors[key] ? t(errors[key]) : serverErrors[key];

  const save = async () => {
    const found = validateEmailForm(form);
    setErrors(found);
    setServerErrors({});
    setBannerErrors([]);
    if (Object.keys(found).length) return;
    setSaving(true);
    try {
      const saved = await api.saveProvider(realmId, toWrite(form));
      const fresh = formFromProvider(driver, saved);
      setBaselines((b) => ({ ...b, [driver]: fresh }));
      setDrafts((d) => ({ ...d, [driver]: fresh }));
      await onChanged();
      onSaved();
    } catch (e) {
      if (e instanceof MessagingApiError && Object.keys(e.fieldErrors).length) {
        const split = splitServerErrors(driver, e.fieldErrors);
        setServerErrors(split.fields);
        setBannerErrors(split.other);
      } else {
        setBannerErrors([String((e as Error).message ?? e)]);
      }
    } finally {
      setSaving(false);
    }
  };

  const discard = () => {
    setDrafts((d) => ({ ...d, [driver]: baseline }));
    setErrors({});
    setServerErrors({});
    setBannerErrors([]);
  };

  const turnOff = async (other: string) => {
    const p = providers.find((x) => x.channel === "EMAIL" && x.driver === other);
    if (!p) return;
    setTurningOff(other);
    try {
      await api.saveProvider(realmId, { channel: "EMAIL", driver: other, enabled: false, fromAddress: p.fromAddress, fromName: p.fromName, config: p.config, secret: null });
      await onChanged();
    } catch (e) {
      setBannerErrors([t("email.others.turnOffFailed", { driver: t(`email.driver.${other}.title`) }) + " " + String((e as Error).message ?? e)]);
    } finally {
      setTurningOff(null);
    }
  };

  const hasErrors = Object.keys(errors).length > 0 || Object.keys(serverErrors).length > 0 || bannerErrors.length > 0;

  return (
    <div className="hx-stack">
      <Section
        title={t("email.provider.title")}
        description={t("email.provider.description")}
        actions={<StatusBadge providers={providers} />}
      >
        {!anyEnabled && <Alert tone="info" title={t("email.fallback.title")}>{t("email.fallback.body")}</Alert>}
        <FormField label={t("email.driver.label")} hint={t("email.driver.hint")} group="radiogroup">
          <div className="hx-choicegrid">
            {EMAIL_DRIVERS.map((d) => (
              <RadioCard
                key={d}
                selected={driver === d}
                onSelect={() => chooseDriver(d)}
                title={<>{t(`email.driver.${d}.title`)}{driverTag(d, t)}{tileStatus(findEmail(providers, d), t)}</>}
                description={t(`email.driver.${d}.description`)}
              />
            ))}
          </div>
        </FormField>

        {others.length > 0 && (
          <Alert tone={form.enabled ? "warning" : "info"} title={form.enabled ? t("email.others.title") : t("email.others.activeTitle")}>
            {form.enabled ? t("email.others.bodyEnabled", { drivers: others.map((o) => t(`email.driver.${o}.title`)).join(", ") })
              : t("email.others.bodyDisabled", { drivers: others.map((o) => t(`email.driver.${o}.title`)).join(", ") })}
            {form.enabled && (
              <div className="hx-inlineactions">
                {others.map((o) => (
                  <Button key={o} variant="ghost" onClick={() => turnOff(o)} disabled={turningOff !== null}>
                    {t("email.others.turnOff", { driver: t(`email.driver.${o}.title`) })}
                  </Button>
                ))}
              </div>
            )}
          </Alert>
        )}

        <div className="hx-switchrow">
          <div className="hx-switchrow__text">
            <span className="hx-switchrow__title" id="email-enabled-label">{t("email.enabled.label", { driver: t(`email.driver.${driver}.title`) })}</span>
            <span className="hx-help">{t("email.enabled.hint")}</span>
          </div>
          <Switch checked={form.enabled} onChange={(on) => update({ ...form, enabled: on })} ariaLabelledby="email-enabled-label" />
        </div>
      </Section>

      <Section title={t("email.sender.title")} description={driver === "LOG" ? t("email.sender.descriptionLog") : t("email.sender.description")}>
        <div className="hx-fieldgrid">
          <FormField label={t("email.field.fromAddress")} required={driver !== "LOG"} error={fieldError("fromAddress")} hint={t("email.field.fromAddress.hint")}>
            <Input type="email" value={form.fromAddress} onChange={(e) => update({ ...form, fromAddress: e.target.value })} placeholder="no-reply@example.com" autoComplete="off" aria-invalid={!!fieldError("fromAddress")} />
          </FormField>
          <FormField label={t("email.field.fromName")} error={fieldError("fromName")} hint={t("email.field.fromName.hint")}>
            <Input value={form.fromName} onChange={(e) => update({ ...form, fromName: e.target.value })} placeholder={t("email.field.fromName.placeholder")} autoComplete="off" aria-invalid={!!fieldError("fromName")} />
          </FormField>
        </div>
      </Section>

      {driver === "SMTP" && <SmtpSection form={form} update={update} setConfig={setConfig} fieldError={fieldError} />}
      {driver === "CLOUDFLARE" && <CloudflareSection form={form} update={update} setConfig={setConfig} fieldError={fieldError} />}
      {driver === "HTTP" && <HttpSection form={form} update={update} setConfig={setConfig} fieldError={fieldError} />}
      {driver === "LOG" && (
        <Section title={t("email.log.title")}>
          <Alert tone="warning" title={t("email.log.alertTitle")}>{t("email.log.alertBody")}</Alert>
        </Section>
      )}

      {hasErrors && (
        <Alert tone="danger" title={t("email.save.errorTitle")}>
          {bannerErrors.length > 0 ? bannerErrors.map((m) => <div key={m}>{m}</div>) : t("email.save.errorBody")}
        </Alert>
      )}
      <div className="hx-savebar">
        <span className="hx-help">{dirty ? <span className="hx-unsaved">{t("email.save.unsaved")}</span> : t("email.save.saved")}</span>
        <div className="hx-savebar__actions">
          {existing && isDirty(form, baseline) && <Button variant="ghost" onClick={discard} disabled={saving}>{t("email.save.discard")}</Button>}
          <Button variant="primary" onClick={save} disabled={saving || !dirty}>{saving ? t("email.save.saving") : t("email.save.action")}</Button>
        </div>
      </div>

      <TestEmail api={api} realmId={realmId} driver={driver} existing={existing} dirty={isDirty(form, baseline)} otherEnabled={others.length > 0} />
    </div>
  );
}

/** Keep the from address and name when switching to a driver that has no saved row yet. */
function carryFrom(drafts: Drafts, providers: MessagingProvider[]): { fromAddress: string; fromName: string } | undefined {
  const draft = Object.values(drafts).find((d) => d && d.fromAddress);
  if (draft) return { fromAddress: draft.fromAddress, fromName: draft.fromName };
  const saved = providers.find((p) => p.channel === "EMAIL" && p.fromAddress);
  return saved ? { fromAddress: saved.fromAddress ?? "", fromName: saved.fromName ?? "" } : undefined;
}

function driverTag(d: EmailDriver, t: (k: string) => string) {
  if (d === "HTTP") return <span className="hx-tile__tag"><Badge tone="neutral">{t("email.driver.HTTP.tag")}</Badge></span>;
  if (d === "LOG") return <span className="hx-tile__tag"><Badge tone="warning">{t("email.driver.LOG.tag")}</Badge></span>;
  return null;
}

function tileStatus(p: MessagingProvider | undefined, t: (k: string) => string) {
  if (!p) return null;
  return <span className="hx-tile__tag">{p.enabled ? <Badge tone="success">{t("email.status.on")}</Badge> : <Badge tone="neutral">{t("email.status.off")}</Badge>}</span>;
}

function StatusBadge({ providers }: { providers: MessagingProvider[] }) {
  const { t } = useT();
  const active = providers.find((p) => p.channel === "EMAIL" && p.enabled);
  return active
    ? <Badge tone="success">{t("email.status.sendingWith", { driver: t(`email.driver.${active.driver}.title`) })}</Badge>
    : <Badge tone="neutral">{t("email.status.serverDefault")}</Badge>;
}

interface DriverSectionProps {
  form: EmailForm;
  update: (f: EmailForm) => void;
  setConfig: (key: string, value: string) => void;
  fieldError: (key: string) => string | undefined;
}

function SmtpSection({ form, update, setConfig, fieldError }: DriverSectionProps) {
  const { t } = useT();
  const mode = resolveTlsMode(form.config);
  const advancedHasValue = ["caBundle", "connectTimeoutMs", "readTimeoutMs", "ehloName"].some((k) => (form.config[k] ?? "").trim() || fieldError(`config.${k}`));
  return (
    <Section title={t("email.smtp.title")} description={t("email.smtp.description")}>
      <div className="hx-fieldgrid hx-fieldgrid--narrow">
        <FormField label={t("email.field.host")} required error={fieldError("config.host")}>
          <Input value={form.config.host ?? ""} onChange={(e) => setConfig("host", e.target.value)} placeholder="smtp.example.com" autoComplete="off" spellCheck={false} aria-invalid={!!fieldError("config.host")} />
        </FormField>
        <FormField label={t("email.field.port")} error={fieldError("config.port")} hint={form.portTouched ? t("email.field.port.typed") : t("email.field.port.auto")}>
          <Input inputMode="numeric" value={form.config.port ?? ""} onChange={(e) => update(setPort(form, e.target.value))} placeholder={String(defaultPort(mode))} aria-invalid={!!fieldError("config.port")} />
        </FormField>
      </div>

      <FormField label={t("email.field.tlsMode")} group="radiogroup" error={fieldError("config.tlsMode")}>
        <div className="hx-choicegrid hx-choicegrid--compact">
          {TLS_MODES.map((m: TlsMode) => (
            <RadioCard key={m} selected={mode === m} onSelect={() => update(setTlsMode(form, m))}
              title={t(`email.tls.${m}.title`)} description={t(`email.tls.${m}.description`)} />
          ))}
        </div>
      </FormField>
      {mode === "NONE" && <Alert tone="warning" title={t("email.tls.NONE.alertTitle")}>{t("email.tls.NONE.alertBody")}</Alert>}

      <div className="hx-fieldgrid hx-mt-3">
        <FormField label={t("email.field.username")} error={fieldError("config.username")} hint={t("email.field.username.hint")}>
          <Input value={form.config.username ?? ""} onChange={(e) => setConfig("username", e.target.value)} autoComplete="off" spellCheck={false} />
        </FormField>
        <SecretField label={t("email.secret.password")} form={form} update={update} error={fieldError("secret")} hint={t("email.secret.password.hint")} />
      </div>

      <details className="hx-disclosure" open={advancedHasValue || undefined}>
        <summary>{t("email.advanced")} <span className="hx-disclosure__hint">{t("email.smtp.advanced.hint")}</span></summary>
        <div className="hx-disclosure__body">
          <div className="hx-fieldgrid">
            <FormField label={t("email.field.connectTimeout")} error={fieldError("config.connectTimeoutMs")} hint={t("email.field.timeout.hint", { ms: EMAIL_DEFAULTS.SMTP.connectTimeoutMs })}>
              <Input inputMode="numeric" value={form.config.connectTimeoutMs ?? ""} onChange={(e) => setConfig("connectTimeoutMs", e.target.value)} placeholder={EMAIL_DEFAULTS.SMTP.connectTimeoutMs} />
            </FormField>
            <FormField label={t("email.field.readTimeout")} error={fieldError("config.readTimeoutMs")} hint={t("email.field.timeout.hint", { ms: EMAIL_DEFAULTS.SMTP.readTimeoutMs })}>
              <Input inputMode="numeric" value={form.config.readTimeoutMs ?? ""} onChange={(e) => setConfig("readTimeoutMs", e.target.value)} placeholder={EMAIL_DEFAULTS.SMTP.readTimeoutMs} />
            </FormField>
            <FormField label={t("email.field.ehloName")} error={fieldError("config.ehloName")} hint={t("email.field.ehloName.hint")}>
              <Input value={form.config.ehloName ?? ""} onChange={(e) => setConfig("ehloName", e.target.value)} placeholder="mail.example.com" spellCheck={false} />
            </FormField>
          </div>
          <CaBundleField form={form} setConfig={setConfig} error={fieldError("config.caBundle")} />
        </div>
      </details>
    </Section>
  );
}

function CloudflareSection({ form, update, setConfig, fieldError }: DriverSectionProps) {
  const { t } = useT();
  const advancedHasValue = ["baseUrl", "connectTimeoutMs", "readTimeoutMs", "caBundle"].some((k) => (form.config[k] ?? "").trim() || fieldError(`config.${k}`));
  return (
    <Section title={t("email.cf.title")} description={t("email.cf.description")}>
      <Alert tone="info" title={t("email.cf.prereq.title")}>
        <ul className="hx-checklist">
          <li className="hx-checklist__item">{t("email.cf.prereq.token")}</li>
          <li className="hx-checklist__item">{t("email.cf.prereq.domain")}</li>
          <li className="hx-checklist__item">{t("email.cf.prereq.account")}</li>
        </ul>
      </Alert>
      <div className="hx-fieldgrid hx-mt-3">
        <FormField label={t("email.field.accountId")} required error={fieldError("config.accountId")} hint={t("email.field.accountId.hint")}>
          <Input className="hx-mono" value={form.config.accountId ?? ""} onChange={(e) => setConfig("accountId", e.target.value)} placeholder="023e105f4ecef8ad9ca31a8372d0c353" autoComplete="off" spellCheck={false} aria-invalid={!!fieldError("config.accountId")} />
        </FormField>
        <SecretField label={t("email.secret.apiToken")} form={form} update={update} required error={fieldError("secret")} hint={t("email.secret.apiToken.hint")} />
      </div>
      <details className="hx-disclosure" open={advancedHasValue || undefined}>
        <summary>{t("email.advanced")} <span className="hx-disclosure__hint">{t("email.cf.advanced.hint")}</span></summary>
        <div className="hx-disclosure__body">
          <FormField label={t("email.field.baseUrl")} error={fieldError("config.baseUrl")} hint={t("email.field.baseUrl.hint")}>
            <Input className="hx-mono" value={form.config.baseUrl ?? ""} onChange={(e) => setConfig("baseUrl", e.target.value)} placeholder={EMAIL_DEFAULTS.CLOUDFLARE.baseUrl} spellCheck={false} aria-invalid={!!fieldError("config.baseUrl")} />
          </FormField>
          <div className="hx-fieldgrid">
            <FormField label={t("email.field.connectTimeout")} error={fieldError("config.connectTimeoutMs")} hint={t("email.field.timeout.hint", { ms: EMAIL_DEFAULTS.CLOUDFLARE.connectTimeoutMs })}>
              <Input inputMode="numeric" value={form.config.connectTimeoutMs ?? ""} onChange={(e) => setConfig("connectTimeoutMs", e.target.value)} placeholder={EMAIL_DEFAULTS.CLOUDFLARE.connectTimeoutMs} />
            </FormField>
            <FormField label={t("email.field.readTimeout")} error={fieldError("config.readTimeoutMs")} hint={t("email.field.timeout.hint", { ms: EMAIL_DEFAULTS.CLOUDFLARE.readTimeoutMs })}>
              <Input inputMode="numeric" value={form.config.readTimeoutMs ?? ""} onChange={(e) => setConfig("readTimeoutMs", e.target.value)} placeholder={EMAIL_DEFAULTS.CLOUDFLARE.readTimeoutMs} />
            </FormField>
          </div>
          <CaBundleField form={form} setConfig={setConfig} error={fieldError("config.caBundle")} />
        </div>
      </details>
    </Section>
  );
}

function HttpSection({ form, update, setConfig, fieldError }: DriverSectionProps) {
  const { t } = useT();
  return (
    <Section title={t("email.http.title")} description={t("email.http.description")}>
      <FormField label={t("email.field.relayUrl")} required error={fieldError("config.url")}>
        <Input className="hx-mono" value={form.config.url ?? ""} onChange={(e) => setConfig("url", e.target.value)} placeholder="https://relay.example.com/send" spellCheck={false} aria-invalid={!!fieldError("config.url")} />
      </FormField>
      <div className="hx-fieldgrid">
        <FormField label={t("email.field.authHeader")} error={fieldError("config.authHeader")} hint={t("email.field.authHeader.hint")}>
          <Input value={form.config.authHeader ?? ""} onChange={(e) => setConfig("authHeader", e.target.value)} placeholder="Authorization" spellCheck={false} />
        </FormField>
        <FormField label={t("email.field.authScheme")} error={fieldError("config.authScheme")} hint={t("email.field.authScheme.hint")}>
          <Input value={form.config.authScheme ?? ""} onChange={(e) => setConfig("authScheme", e.target.value)} placeholder="Bearer " spellCheck={false} />
        </FormField>
      </div>
      <SecretField label={t("email.secret.relayKey")} form={form} update={update} error={fieldError("secret")} hint={t("email.secret.relayKey.hint")} />
    </Section>
  );
}

/**
 * A write-only secret: "Set" / "Not set" and a Replace action. The stored value is never shown or prefilled; an
 * empty field is never sent (the API keeps the stored secret when none is given).
 */
function SecretField({ label, form, update, error, hint, required }: {
  label: string; form: EmailForm; update: (f: EmailForm) => void; error?: string; hint?: string; required?: boolean;
}) {
  const { t } = useT();
  const s = form.secret;
  const inputRef = React.useRef<HTMLInputElement>(null);
  const editing = !s.stored || s.replacing;
  React.useEffect(() => { if (s.replacing) inputRef.current?.focus(); }, [s.replacing]);
  const set = (next: Partial<typeof s>) => update({ ...form, secret: { ...s, ...next } });
  return (
    <FormField label={label} required={required && !s.stored} group error={error} hint={hint}>
      <div className="hx-secretstate">
        {s.stored ? <Badge tone="success">{t("email.secret.set")}</Badge> : <Badge tone="neutral">{t("email.secret.notSet")}</Badge>}
        {editing && (
          <Input ref={inputRef} type="password" value={s.value} onChange={(e) => set({ value: e.target.value })}
            placeholder={s.stored ? t("email.secret.newPlaceholder") : t("email.secret.placeholder")}
            autoComplete="new-password" spellCheck={false} aria-label={label} aria-invalid={!!error} />
        )}
        {s.stored && !s.replacing && <Button variant="ghost" onClick={() => set({ replacing: true, value: "" })}>{t("email.secret.replace")}</Button>}
        {s.stored && s.replacing && <Button variant="ghost" onClick={() => set({ replacing: false, value: "" })}>{t("email.secret.keep")}</Button>}
      </div>
    </FormField>
  );
}

function CaBundleField({ form, setConfig, error }: { form: EmailForm; setConfig: (k: string, v: string) => void; error?: string }) {
  const { t } = useT();
  const fileRef = React.useRef<HTMLInputElement>(null);
  const load = (file: File | undefined) => {
    if (!file) return;
    file.text().then((text) => setConfig("caBundle", text)).catch(() => undefined);
  };
  return (
    <FormField label={t("email.field.caBundle")} error={error} hint={t("email.field.caBundle.hint")} group>
      <Textarea className="hx-mono" rows={4} value={form.config.caBundle ?? ""} onChange={(e) => setConfig("caBundle", e.target.value)}
        placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"} spellCheck={false} aria-label={t("email.field.caBundle")} aria-invalid={!!error} />
      <div className="hx-inlineactions">
        <Button variant="ghost" onClick={() => fileRef.current?.click()}>{t("email.field.caBundle.load")}</Button>
        {(form.config.caBundle ?? "").trim() && <Button variant="ghost" onClick={() => setConfig("caBundle", "")}>{t("email.field.caBundle.clear")}</Button>}
        <input ref={fileRef} type="file" accept=".pem,.crt,.cer,text/plain" className="hx-visually-hidden" tabIndex={-1}
          onChange={(e) => { load(e.target.files?.[0]); e.target.value = ""; }} />
      </div>
    </FormField>
  );
}

function TestEmail({ api, realmId, driver, existing, dirty, otherEnabled }: {
  api: MessagingApi; realmId: string; driver: EmailDriver; existing?: MessagingProvider; dirty: boolean; otherEnabled: boolean;
}) {
  const { t } = useT();
  const [to, setTo] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [view, setView] = React.useState<TestResultView | null>(null);
  React.useEffect(() => { setView(null); setError(null); }, [driver]);

  const ready = !!existing && existing.enabled;
  const send = async () => {
    const problem = validateTestRecipient(to);
    setError(problem);
    if (problem) return;
    setBusy(true);
    setView(null);
    try {
      setView(describeTestResult(await api.testProvider(realmId, "EMAIL", to.trim()), driver));
    } catch (e) {
      setView({ tone: "danger", title: "email.test.notSent", message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const note = !existing ? t("email.test.needSave") : !existing.enabled ? t("email.test.needEnabled")
    : dirty ? t("email.test.unsaved") : otherEnabled ? t("email.test.otherEnabled") : null;

  return (
    <Section title={t("email.test.title")} description={t("email.test.description")}>
      {note && <Alert tone={ready ? "warning" : "info"}>{note}</Alert>}
      <FormField label={t("email.test.to")} error={error ? t(error) : undefined} hint={t("email.test.to.hint")}>
        <div className="hx-inputrow hx-inputrow--stack">
          <Input type="email" value={to} onChange={(e) => { setTo(e.target.value); if (error) setError(validateTestRecipient(e.target.value)); }}
            onKeyDown={(e) => { if (e.key === "Enter" && ready && !busy) send(); }}
            placeholder="you@example.com" autoComplete="email" disabled={!ready} aria-invalid={!!error} />
          <Button variant="primary" onClick={send} disabled={!ready || busy}>{busy ? t("email.test.sending") : t("email.test.action")}</Button>
        </div>
      </FormField>
      {view && (
        <Alert tone={view.tone} title={t(view.title)} onDismiss={() => setView(null)}>
          <div className="hx-testresult">
            <div>{view.reason ? t(view.reason) : view.message}</div>
            {view.guidance && <div className="hx-testresult__guide">{t(view.guidance)}</div>}
            {view.diagnostic && (
              <div>
                <span className="hx-testresult__label">{t("email.test.diagnostic")}</span>
                <pre className="hx-codeblock">{view.diagnostic}</pre>
              </div>
            )}
            {view.providerMessageId && (
              <div>
                <span className="hx-testresult__label">{t("email.test.messageId")}</span>
                <span className="hx-mono">{view.providerMessageId}</span>
              </div>
            )}
          </div>
        </Alert>
      )}
    </Section>
  );
}
