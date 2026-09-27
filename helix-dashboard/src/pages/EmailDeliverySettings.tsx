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
import { ConfirmDialog, Modal } from "../components/Modal";
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
  activeEmailProvider,
  clearSecretBlocked,
  clearSecretWrite,
  switchesFrom,
  Carry,
  SEND_LIMIT_RANGE,
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
  /** Reload the provider list after a change (without unmounting this form); resolves to the fresh list. */
  onChanged: () => Promise<MessagingProvider[]>;
  onSaved: () => void;
}

type Drafts = Partial<Record<EmailDriver, EmailForm>>;

const findEmail = (providers: MessagingProvider[], driver: EmailDriver) =>
  providers.find((p) => p.channel === "EMAIL" && p.driver === driver);

/**
 * Email tab of Notifications: choose how this realm sends email (SMTP, Cloudflare Email Service, an HTTP relay or
 * the dev log), configure it with write-only secrets and the realm's send rate cap, and send a classified test email
 * through any saved provider. The server keeps one enabled email provider per realm: saving one switched on makes it
 * the realm's sender and turns the previous one off, which the page confirms first.
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
  const [confirmSwitch, setConfirmSwitch] = React.useState<string | null>(null);
  const [confirmRemove, setConfirmRemove] = React.useState(false);
  const [removing, setRemoving] = React.useState(false);

  const existing = findEmail(providers, driver);
  const anyEnabled = providers.some((p) => p.channel === "EMAIL" && p.enabled);
  const baseline = baselines[driver] ?? formFromProvider(driver, existing, carryFrom(drafts, providers), !anyEnabled);
  const form = drafts[driver] ?? baseline;
  const dirty = !existing || isDirty(form, baseline);
  const active = activeEmailProvider(providers);
  const switching = switchesFrom(providers, form);
  const turningEmailOff = !!existing?.enabled && !form.enabled;
  const removeBlocked = clearSecretBlocked(existing);
  const driverName = (d: string) => t(`email.driver.${d}.title`);

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

  /** After a save the server may have switched other providers off: bring their drafts in line with the fresh list. */
  const syncOthers = (fresh: MessagingProvider[]) => {
    const sync = (all: Drafts): Drafts => {
      const next: Drafts = { ...all };
      for (const d of EMAIL_DRIVERS) {
        const f = next[d];
        const p = findEmail(fresh, d);
        if (d !== driver && f && p) next[d] = { ...f, enabled: p.enabled };
      }
      return next;
    };
    setDrafts(sync);
    setBaselines(sync);
  };

  const save = () => {
    const found = validateEmailForm(form);
    setErrors(found);
    setServerErrors({});
    setBannerErrors([]);
    if (Object.keys(found).length) return;
    if (switching) {
      setConfirmSwitch(switching);
      return;
    }
    void persist();
  };

  const persist = async () => {
    setConfirmSwitch(null);
    setSaving(true);
    try {
      const saved = await api.saveProvider(realmId, toWrite(form));
      const fresh = formFromProvider(driver, saved);
      setBaselines((b) => ({ ...b, [driver]: fresh }));
      setDrafts((d) => ({ ...d, [driver]: fresh }));
      syncOthers(await onChanged());
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

  /** Remove the stored secret of the saved provider (not the draft: unsaved edits stay unsaved). */
  const removeSecret = async () => {
    setConfirmRemove(false);
    if (!existing || removeBlocked) return;
    setRemoving(true);
    setBannerErrors([]);
    try {
      await api.saveProvider(realmId, clearSecretWrite(existing));
      const cleared = (f: EmailForm | undefined) => f && { ...f, secret: { stored: false, replacing: false, value: "" } };
      setBaselines((b) => ({ ...b, [driver]: cleared(b[driver] ?? baseline) }));
      setDrafts((d) => ({ ...d, [driver]: cleared(d[driver] ?? form) }));
      await onChanged();
      onSaved();
    } catch (e) {
      const fields = e instanceof MessagingApiError ? Object.values(e.fieldErrors) : [];
      setBannerErrors(fields.length ? fields : [String((e as Error).message ?? e)]);
    } finally {
      setRemoving(false);
    }
  };
  // The secret's name inside a sentence ("Remove the stored password?").
  const secretLabel = t(driver === "CLOUDFLARE" ? "email.secret.noun.apiToken" : driver === "SMTP" ? "email.secret.noun.password" : "email.secret.noun.relayKey");

  const sectionProps: DriverSectionProps = {
    form, update, setConfig, fieldError, removing,
    onRemoveSecret: () => setConfirmRemove(true),
    removeBlocked,
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

        <div className="hx-switchrow">
          <div className="hx-switchrow__text">
            <span className="hx-switchrow__title" id="email-enabled-label">{t("email.enabled.label", { driver: driverName(driver) })}</span>
            <span className="hx-help">{t("email.enabled.hint")}</span>
          </div>
          <Switch checked={form.enabled} onChange={(on) => update({ ...form, enabled: on })} ariaLabelledby="email-enabled-label" />
        </div>
        {switching && (
          <Alert tone="info" title={t("email.switch.title", { driver: driverName(driver) })}>
            {t("email.switch.body", { driver: driverName(driver), current: driverName(switching) })}
          </Alert>
        )}
        {turningEmailOff && (
          <Alert tone="warning" title={t("email.off.title", { driver: driverName(driver) })}>{t("email.off.body", { driver: driverName(driver) })}</Alert>
        )}
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

      {driver === "SMTP" && <SmtpSection {...sectionProps} />}
      {driver === "CLOUDFLARE" && <CloudflareSection {...sectionProps} />}
      {driver === "HTTP" && <HttpSection {...sectionProps} />}
      {driver === "LOG" && (
        <Section title={t("email.log.title")}>
          <Alert tone="warning" title={t("email.log.alertTitle")}>{t("email.log.alertBody")}</Alert>
        </Section>
      )}

      <Section title={t("email.limit.title")} description={t("email.limit.description")}>
        <div className="hx-fieldgrid">
          <FormField label={t("email.field.sendLimit")} error={fieldError("config.sendLimitPerMinute")}
            hint={t("email.field.sendLimit.hint", { min: SEND_LIMIT_RANGE.min, max: SEND_LIMIT_RANGE.max })}>
            <Input inputMode="numeric" value={form.config.sendLimitPerMinute ?? ""} onChange={(e) => setConfig("sendLimitPerMinute", e.target.value)}
              placeholder={t("email.field.sendLimit.placeholder")} aria-invalid={!!fieldError("config.sendLimitPerMinute")} />
          </FormField>
          <div className="hx-field hx-help hx-limitnote">{t("email.limit.note")}</div>
        </div>
      </Section>

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

      {/* Keyed by the saved provider: a result from before the last save no longer describes these settings. */}
      <TestEmail key={`${driver}:${existing ? JSON.stringify(existing) : "new"}`} api={api} realmId={realmId} driver={driver} existing={existing} dirty={isDirty(form, baseline)} />

      <Modal open={confirmSwitch !== null} title={t("email.switch.confirmTitle", { driver: driverName(driver) })} onClose={() => setConfirmSwitch(null)} width={480}
        footer={<>
          <Button variant="ghost" onClick={() => setConfirmSwitch(null)}>{t("common.cancel")}</Button>
          <Button variant="primary" onClick={() => void persist()}>{t("email.switch.confirm", { driver: driverName(driver) })}</Button>
        </>}>
        <p className="hx-modal__lede">{confirmSwitch && t("email.switch.confirmBody", { driver: driverName(driver), current: driverName(confirmSwitch) })}</p>
      </Modal>

      <ConfirmDialog open={confirmRemove} title={t("email.secret.remove.confirmTitle", { secret: secretLabel })}
        message={t(active?.driver === driver ? "email.secret.remove.confirmBodyActive" : "email.secret.remove.confirmBody", { secret: secretLabel, driver: driverName(driver) })}
        confirmLabel={t("email.secret.remove.confirm", { secret: secretLabel })} cancelLabel={t("common.cancel")}
        onConfirm={() => void removeSecret()} onCancel={() => setConfirmRemove(false)} />
    </div>
  );
}

/** Keep the from address, name and send rate cap when switching to a driver that has no saved row yet. */
function carryFrom(drafts: Drafts, providers: MessagingProvider[]): Carry | undefined {
  const draft = Object.values(drafts).find((d) => d && d.fromAddress);
  if (draft) return { fromAddress: draft.fromAddress, fromName: draft.fromName, sendLimitPerMinute: draft.config.sendLimitPerMinute };
  const saved = activeEmailProvider(providers) ?? providers.find((p) => p.channel === "EMAIL" && p.fromAddress);
  return saved ? { fromAddress: saved.fromAddress ?? "", fromName: saved.fromName ?? "", sendLimitPerMinute: saved.config?.sendLimitPerMinute } : undefined;
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
  /** Remove the stored secret (asks first); `removeBlocked` is an i18n key when it can't be removed. */
  onRemoveSecret: () => void;
  removeBlocked: string | null;
  removing: boolean;
}

function SmtpSection({ form, update, setConfig, fieldError, onRemoveSecret, removeBlocked, removing }: DriverSectionProps) {
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
        <SecretField label={t("email.secret.password")} form={form} update={update} onRemove={onRemoveSecret} removeBlocked={removeBlocked} removing={removing} error={fieldError("secret")} hint={t("email.secret.password.hint")} />
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

function CloudflareSection({ form, update, setConfig, fieldError, onRemoveSecret, removeBlocked, removing }: DriverSectionProps) {
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
        <SecretField label={t("email.secret.apiToken")} form={form} update={update} onRemove={onRemoveSecret} removeBlocked={removeBlocked} removing={removing} required error={fieldError("secret")} hint={t("email.secret.apiToken.hint")} />
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

function HttpSection({ form, update, setConfig, fieldError, onRemoveSecret, removeBlocked, removing }: DriverSectionProps) {
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
      <SecretField label={t("email.secret.relayKey")} form={form} update={update} onRemove={onRemoveSecret} removeBlocked={removeBlocked} removing={removing} error={fieldError("secret")} hint={t("email.secret.relayKey.hint")} />
    </Section>
  );
}

/**
 * A write-only secret: "Set" / "Not set" and a Replace action. The stored value is never shown or prefilled; an
 * empty field is never sent (the API keeps the stored secret when none is given).
 */
function SecretField({ label, form, update, error, hint, required, onRemove, removeBlocked, removing }: {
  label: string; form: EmailForm; update: (f: EmailForm) => void; error?: string; hint?: string; required?: boolean;
  onRemove: () => void; removeBlocked: string | null; removing: boolean;
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
        {s.stored && !s.replacing && (
          <Button variant="ghost" className={removeBlocked ? undefined : "hx-btn--danger"} onClick={onRemove} disabled={removing || removeBlocked === "email.secret.remove.blockedCloudflare"}>
            {removing ? t("email.secret.removing") : t("email.secret.remove")}
          </Button>
        )}
        {s.stored && s.replacing && <Button variant="ghost" onClick={() => set({ replacing: false, value: "" })}>{t("email.secret.keep")}</Button>}
      </div>
      {s.stored && !s.replacing && removeBlocked === "email.secret.remove.blockedCloudflare" && (
        <span className="hx-field__hint">{t(removeBlocked)}</span>
      )}
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

function TestEmail({ api, realmId, driver, existing, dirty }: {
  api: MessagingApi; realmId: string; driver: EmailDriver; existing?: MessagingProvider; dirty: boolean;
}) {
  const { t } = useT();
  const [to, setTo] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [view, setView] = React.useState<TestResultView | null>(null);
  React.useEffect(() => { setView(null); setError(null); }, [driver]);

  // Any saved provider can be tested, also one that is switched off: the test names the driver.
  const ready = !!existing;
  const send = async () => {
    const problem = validateTestRecipient(to);
    setError(problem);
    if (problem) return;
    setBusy(true);
    setView(null);
    try {
      setView(describeTestResult(await api.testProvider(realmId, "EMAIL", to.trim(), driver), driver));
    } catch (e) {
      setView({ tone: "danger", title: "email.test.notSent", message: String((e as Error).message ?? e) });
    } finally {
      setBusy(false);
    }
  };

  const note = !existing ? t("email.test.needSave") : dirty ? t("email.test.unsaved")
    : !existing.enabled ? t("email.test.offProvider", { driver: t(`email.driver.${driver}.title`) }) : null;
  const noteTone = !existing ? "info" : dirty ? "warning" : "info";

  return (
    <Section title={t("email.test.title")} description={t("email.test.description")}>
      {note && <Alert tone={noteTone}>{note}</Alert>}
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
