/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Page, PageHeader, PageBody, Section } from "../components/Page";
import { Button } from "../components/Button";
import { Divider } from "../components/Divider";
import { Tabs } from "../components/Tabs";
import { FormField, Input, Textarea } from "../components/FormField";
import { Select } from "../components/Select";
import { Checkbox } from "../components/Choice";
import { Toast, ToastTone } from "../components/Toast";
import { Badge } from "../components/Badge";
import { Spinner } from "../components/Spinner";
import { MessagingApi, MessagingProvider, MessageTemplate } from "../api/messaging";
import { useT } from "../i18n/LocaleContext";

export interface NotificationsPageProps {
  api: MessagingApi;
  realmId: string;
}

interface Note { tone: ToastTone; title: string; message?: string; }

type Target = "config" | "from" | "fromName" | "secret";
interface Field { key: string; label: string; target: Target; type?: "text" | "password" | "textarea"; placeholder?: string; hint?: string; }

/** Per (channel → driver) field schema. Label and hint values are i18n keys resolved via t() at render time. */
const SCHEMA: Record<string, { label: string; drivers: Record<string, { label: string; fields: Field[]; secretLabel: string }> }> = {
  SMS: {
    label: "notifications.tab.sms",
    drivers: {
      TWILIO: { label: "notifications.driver.twilio", secretLabel: "notifications.secret.authToken", fields: [
        { key: "accountSid", label: "notifications.field.accountSid", target: "config", placeholder: "ACxxxxxxxx" },
        { key: "from", label: "notifications.field.fromNumber", target: "from", placeholder: "+15550100" },
      ] },
      HTTP: { label: "notifications.driver.httpSms", secretLabel: "notifications.secret.bearerToken", fields: [
        { key: "url", label: "notifications.field.webhookUrl", target: "config", placeholder: "https://gateway.example/send" },
        { key: "bodyTemplate", label: "notifications.field.bodyTemplate", target: "config", type: "textarea", placeholder: '{"to":"{{to}}","message":"{{message}}"}', hint: "notifications.field.bodyTemplate.hint" },
        { key: "authHeader", label: "notifications.field.authHeader", target: "config", placeholder: "Authorization" },
      ] },
    },
  },
  EMAIL: {
    label: "notifications.tab.email",
    drivers: {
      SMTP: { label: "notifications.driver.smtp", secretLabel: "notifications.secret.password", fields: [
        { key: "host", label: "notifications.field.host", target: "config", placeholder: "smtp.example.com" },
        { key: "port", label: "notifications.field.port", target: "config", placeholder: "587" },
        { key: "username", label: "notifications.field.username", target: "config", placeholder: "apikey" },
        { key: "from", label: "notifications.field.fromAddress", target: "from", placeholder: "no-reply@example.com" },
        { key: "fromName", label: "notifications.field.fromName", target: "fromName", placeholder: "Helix" },
        { key: "starttls", label: "notifications.field.starttls", target: "config", placeholder: "true" },
      ] },
      HTTP: { label: "notifications.driver.httpApi", secretLabel: "notifications.secret.apiKey", fields: [
        { key: "url", label: "notifications.field.apiUrl", target: "config", placeholder: "https://api.sendgrid.com/v3/mail/send" },
        { key: "from", label: "notifications.field.fromAddress", target: "from", placeholder: "no-reply@example.com" },
        { key: "fromName", label: "notifications.field.fromName", target: "fromName" },
        { key: "authHeader", label: "notifications.field.authHeader", target: "config", placeholder: "Authorization" },
      ] },
    },
  },
  PUSH: {
    label: "notifications.tab.push",
    drivers: {
      FCM: { label: "notifications.driver.fcm", secretLabel: "notifications.secret.serviceAccountJson", fields: [
        { key: "projectId", label: "notifications.field.projectId", target: "config", placeholder: "my-firebase-project" },
      ] },
      APNS: { label: "notifications.driver.apns", secretLabel: "notifications.secret.authKey", fields: [
        { key: "keyId", label: "notifications.field.keyId", target: "config" },
        { key: "teamId", label: "notifications.field.teamId", target: "config" },
        { key: "bundleId", label: "notifications.field.bundleId", target: "config", placeholder: "com.example.app" },
      ] },
    },
  },
};

const CHANNELS = ["SMS", "EMAIL", "PUSH", "TEMPLATES"] as const;
type Tab = typeof CHANNELS[number];

/** Helix notifications (N4): configure SMS / Email / Push delivery providers and edit message templates. */
export function NotificationsPage({ api, realmId }: NotificationsPageProps) {
  const { t } = useT();
  const [tab, setTab] = React.useState<Tab>("SMS");
  const [providers, setProviders] = React.useState<MessagingProvider[] | null>(null);
  const [templates, setTemplates] = React.useState<MessageTemplate[]>([]);
  const [note, setNote] = React.useState<Note | null>(null);

  const reload = React.useCallback(() => {
    setProviders(null);
    api.listProviders(realmId).then(setProviders).catch((e) => { setProviders([]); setNote({ tone: "error", title: t("notifications.toast.loadError"), message: String(e.message ?? e) }); });
    api.listTemplates(realmId).then(setTemplates).catch(() => setTemplates([]));
  }, [api, realmId]);
  React.useEffect(reload, [reload]);

  return (
    <Page>
      <PageHeader
        title={t("notifications.title")}
        description={t("notifications.description", { realmId })}
        actions={<Button variant="ghost" onClick={reload} disabled={providers === null}>{t("notifications.action.refresh")}</Button>}
      />

      <PageBody>
        <Tabs
          tabs={CHANNELS.map((c) => ({ id: c, label: c === "TEMPLATES" ? t("notifications.tab.templates") : t(SCHEMA[c].label) }))}
          value={tab}
          onChange={(id) => setTab(id as Tab)}
        />

        {providers === null ? (
          <div className="hx-loadwrap"><Spinner size={28} label={t("common.loading")} /></div>
        ) : tab === "TEMPLATES" ? (
          <TemplatesEditor api={api} realmId={realmId} templates={templates} onSaved={(tmpl) => { setTemplates(tmpl); setNote({ tone: "success", title: t("notifications.toast.templateSaved") }); }} onError={(m) => setNote({ tone: "error", title: t("notifications.toast.templateSaveError"), message: m })} />
        ) : (
          <ChannelForm key={tab} api={api} realmId={realmId} channel={tab} providers={providers}
            onSaved={() => { reload(); setNote({ tone: "success", title: t("notifications.toast.providerSaved") }); }}
            onError={(m) => setNote({ tone: "error", title: t("notifications.toast.providerSaveError"), message: m })}
            onTested={(r) => setNote({ tone: r.sent ? "success" : "error", title: r.sent ? t("notifications.toast.testSent") : t("notifications.toast.testNotSent"), message: r.message })} />
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

function ChannelForm({ api, realmId, channel, providers, onSaved, onError, onTested }: {
  api: MessagingApi; realmId: string; channel: string; providers: MessagingProvider[];
  onSaved: () => void; onError: (m: string) => void; onTested: (r: { sent: boolean; message: string }) => void;
}) {
  const { t } = useT();
  const drivers = Object.keys(SCHEMA[channel].drivers);
  const [driver, setDriver] = React.useState(drivers[0]);
  // Guard against a stale driver from a previous channel (defensive — the parent also keys this by channel).
  const def = SCHEMA[channel].drivers[driver] ?? SCHEMA[channel].drivers[drivers[0]];
  const existing = providers.find((p) => p.channel === channel && p.driver === driver);

  const [enabled, setEnabled] = React.useState(false);
  const [config, setConfig] = React.useState<Record<string, string>>({});
  const [fromAddress, setFromAddress] = React.useState("");
  const [fromName, setFromName] = React.useState("");
  const [secret, setSecret] = React.useState("");
  const [testTo, setTestTo] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    setEnabled(existing?.enabled ?? false);
    setConfig(existing?.config ?? {});
    setFromAddress(existing?.fromAddress ?? "");
    setFromName(existing?.fromName ?? "");
    setSecret("");
  }, [driver, channel, providers]); // eslint-disable-line react-hooks/exhaustive-deps

  const setField = (f: Field, v: string) => {
    if (f.target === "config") setConfig((c) => ({ ...c, [f.key]: v }));
    else if (f.target === "from") setFromAddress(v);
    else if (f.target === "fromName") setFromName(v);
  };
  const fieldValue = (f: Field) => f.target === "config" ? (config[f.key] ?? "") : f.target === "from" ? fromAddress : f.target === "fromName" ? fromName : "";

  const save = async () => {
    setBusy(true);
    try {
      await api.saveProvider(realmId, { channel, driver, enabled, fromAddress: fromAddress || null, fromName: fromName || null, config, secret: secret || null });
      onSaved();
    } catch (e) { onError(String((e as Error).message ?? e)); } finally { setBusy(false); }
  };
  const test = async () => {
    setBusy(true);
    try { onTested(await api.testProvider(realmId, channel, testTo)); }
    catch (e) { onTested({ sent: false, message: String((e as Error).message ?? e) }); } finally { setBusy(false); }
  };

  return (
    <Section title={t("notifications.channel.section.title")} description={t("notifications.channel.section.description")}>
      <FormField label={t("notifications.channel.provider")} hint={t("notifications.channel.provider.hint")}>
        <Select value={driver} onChange={setDriver} options={drivers.map((d) => ({ value: d, label: t(SCHEMA[channel].drivers[d].label) }))} />
      </FormField>
      <div className="hx-inputrow hx-field">
        <Checkbox label={t("notifications.channel.enabled")} checked={enabled} onChange={setEnabled} />
        {existing && <Badge tone="neutral">{t("notifications.channel.configured")}</Badge>}
      </div>

      {def.fields.map((f) => (
        <FormField key={f.key} label={t(f.label)} hint={f.hint ? t(f.hint) : undefined}>
          {f.type === "textarea"
            ? <Textarea className="hx-mono" value={fieldValue(f)} onChange={(e) => setField(f, e.target.value)} placeholder={f.placeholder} rows={3} />
            : <Input value={fieldValue(f)} onChange={(e) => setField(f, e.target.value)} placeholder={f.placeholder} />}
        </FormField>
      ))}

      <FormField label={t(def.secretLabel)} hint={existing?.secretSet ? t("notifications.channel.secretStored.hint") : undefined}>
        {channel === "PUSH"
          ? <Textarea className="hx-mono" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={existing?.secretSet ? "•••••••• (stored)" : t("notifications.channel.credential.placeholder")} rows={4} />
          : <Input type="password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={existing?.secretSet ? "•••••••• (stored)" : ""} />}
      </FormField>

      <div className="hx-formactions">
        <Button onClick={save} disabled={busy}>{t("notifications.channel.action.save")}</Button>
      </div>

      <Divider />
      <FormField label={t("notifications.channel.test.label")} hint={channel === "EMAIL" ? t("notifications.channel.test.hint.email")
        : channel === "PUSH" ? t("notifications.channel.test.hint.push")
        : t("notifications.channel.test.hint.sms")}>
        <div className="hx-inputrow">
          <Input value={testTo} onChange={(e) => setTestTo(e.target.value)} placeholder={channel === "EMAIL" ? "you@example.com" : channel === "PUSH" ? "device-token…" : "+15551234567"} />
          <Button variant="ghost" onClick={test} disabled={busy || !testTo.trim()}>{t("notifications.channel.test.action")}</Button>
        </div>
      </FormField>
    </Section>
  );
}

function TemplatesEditor({ api, realmId, templates, onSaved, onError }: {
  api: MessagingApi; realmId: string; templates: MessageTemplate[]; onSaved: (tmpl: MessageTemplate[]) => void; onError: (m: string) => void;
}) {
  const { t } = useT();
  const [selectedKey, setSelectedKey] = React.useState(templates[0]?.templateKey ?? "");
  const selected = templates.find((tmpl) => tmpl.templateKey === selectedKey) ?? templates[0];
  const [subject, setSubject] = React.useState(selected?.subject ?? "");
  const [body, setBody] = React.useState(selected?.body ?? "");
  const [html, setHtml] = React.useState(selected?.html ?? false);
  const [preview, setPreview] = React.useState<{ subject: string; body: string }>({ subject: "", body: "" });
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => { setSubject(selected?.subject ?? ""); setBody(selected?.body ?? ""); setHtml(selected?.html ?? false); }, [selectedKey]); // eslint-disable-line react-hooks/exhaustive-deps
  React.useEffect(() => {
    const timer = setTimeout(() => { api.previewTemplate(realmId, subject, body).then(setPreview).catch(() => undefined); }, 250);
    return () => clearTimeout(timer);
  }, [subject, body, api, realmId]);

  if (!selected) return <Section><span className="hx-muted">{t("notifications.templates.empty")}</span></Section>;
  const isEmail = selected.channel === "EMAIL";

  const save = async () => {
    setBusy(true);
    try {
      await api.saveTemplate(realmId, { ...selected, subject: isEmail ? subject : null, body, html: isEmail ? html : false });
      onSaved(await api.listTemplates(realmId));
    } catch (e) { onError(String((e as Error).message ?? e)); } finally { setBusy(false); }
  };

  return (
    <div className="hx-detailgrid">
      <Section title={t("notifications.templates.section.title")} description={t("notifications.templates.section.description")}>
        <FormField label={t("notifications.templates.label.template")}>
          <Select value={selectedKey} onChange={setSelectedKey}
            options={templates.map((tmpl) => ({ value: tmpl.templateKey, label: `${tmpl.templateKey} (${tmpl.channel.toLowerCase()})` }))} />
        </FormField>
        {isEmail && (
          <FormField label={t("notifications.templates.label.subject")}>
            <Input value={subject} onChange={(e) => setSubject(e.target.value)} />
          </FormField>
        )}
        {isEmail && (
          <div className="hx-inputrow hx-field">
            <Checkbox label={t("notifications.templates.htmlEmail")} checked={html} onChange={setHtml} />
            <span className="hx-help">{t("notifications.templates.htmlEmail.hint")}</span>
          </div>
        )}
        <FormField label={t("notifications.templates.label.body")} hint={t("notifications.templates.body.hint")}>
          <Textarea className="hx-mono" value={body} onChange={(e) => setBody(e.target.value)} rows={10} />
        </FormField>
        <div className="hx-formactions">
          <Button onClick={save} disabled={busy}>{t("notifications.templates.action.save")}</Button>
        </div>
      </Section>
      <Section title={isEmail && html ? t("notifications.templates.preview.titleHtml") : t("notifications.templates.preview.title")}>
        <div className="hx-secret">
          {isEmail && (preview.subject
            ? <strong>{preview.subject}</strong>
            : <span className="hx-faint">{t("notifications.templates.preview.noSubject")}</span>)}
          {isEmail && html
            ? <iframe title="HTML email preview" sandbox="" srcDoc={preview.body}
                className="hx-email-preview" />
            : <div className="hx-codeblock">{preview.body}</div>}
        </div>
      </Section>
    </div>
  );
}
