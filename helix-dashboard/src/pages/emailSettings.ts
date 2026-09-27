/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Email delivery settings (console side of the email-delivery feature): the form model for a realm's EMAIL
// messaging provider, its mapping to and from the API, and validation that mirrors the server's
// MessagingProviderValidator. Pure functions only, unit-tested in emailSettings.test.ts. Messages are i18n
// keys; the page resolves them with t().
//
// Extension point: realm-level email policy (stage 2: a per-realm send rate cap) belongs in its own form model
// and validator next to these, not in EmailForm, which is one provider row (channel EMAIL + one driver).

import type { MessagingProvider, MessagingProviderWrite, TestResult } from "../api/messaging";

export type EmailDriver = "SMTP" | "CLOUDFLARE" | "HTTP" | "LOG";
export const EMAIL_DRIVERS: EmailDriver[] = ["SMTP", "CLOUDFLARE", "HTTP", "LOG"];

export type TlsMode = "STARTTLS_REQUIRED" | "STARTTLS_OPTIONAL" | "IMPLICIT" | "NONE";
export const TLS_MODES: TlsMode[] = ["STARTTLS_REQUIRED", "STARTTLS_OPTIONAL", "IMPLICIT", "NONE"];

/** Server-side defaults, shown as placeholders (an empty field means "use the default"). */
export const EMAIL_DEFAULTS = {
  SMTP: { connectTimeoutMs: "10000", readTimeoutMs: "20000" },
  CLOUDFLARE: { connectTimeoutMs: "5000", readTimeoutMs: "15000", baseUrl: "https://api.cloudflare.com/client/v4" },
} as const;

/** The `config` keys each driver's form edits. Other stored keys are kept as they are on save. */
export const DRIVER_CONFIG_KEYS: Record<EmailDriver, string[]> = {
  SMTP: ["host", "port", "tlsMode", "username", "connectTimeoutMs", "readTimeoutMs", "ehloName", "caBundle"],
  CLOUDFLARE: ["accountId", "baseUrl", "connectTimeoutMs", "readTimeoutMs", "caBundle"],
  HTTP: ["url", "authHeader", "authScheme"],
  LOG: [],
};

/** Deprecated config keys: read once to derive tlsMode, never shown and never sent back. */
const DEPRECATED_KEYS = ["starttls"];

/**
 * The write-only secret (SMTP password, Cloudflare API token, HTTP relay key). The stored value is never
 * known to the console: `stored` says whether one exists, `replacing` whether the user chose to replace it,
 * and `value` is what they typed.
 */
export interface SecretState {
  stored: boolean;
  replacing: boolean;
  value: string;
}

export interface EmailForm {
  driver: EmailDriver;
  enabled: boolean;
  fromAddress: string;
  fromName: string;
  config: Record<string, string>;
  /** True once the user typed an SMTP port; until then the port follows the TLS mode. */
  portTouched: boolean;
  secret: SecretState;
}

/** A message for a form field: an i18n key. Keys match the server's fieldErrors keys. */
export type FieldErrors = Record<string, string>;

export function isEmailDriver(value: string | null | undefined): value is EmailDriver {
  return EMAIL_DRIVERS.includes(value as EmailDriver);
}

/** Mirrors SmtpTlsMode.resolve: tlsMode wins, then the deprecated starttls boolean, else STARTTLS_REQUIRED. */
export function resolveTlsMode(config: Record<string, string | undefined>): TlsMode {
  const mode = (config.tlsMode ?? "").trim().toUpperCase();
  if (TLS_MODES.includes(mode as TlsMode)) return mode as TlsMode;
  const legacy = (config.starttls ?? "").trim().toLowerCase();
  if (legacy === "false") return "STARTTLS_OPTIONAL";
  return "STARTTLS_REQUIRED";
}

/** 465 for implicit TLS (SMTPS), else 587 (submission). */
export function defaultPort(mode: TlsMode): number {
  return mode === "IMPLICIT" ? 465 : 587;
}

/** The form for one EMAIL provider row, or a new one (carrying the from address/name across drivers). */
export function formFromProvider(
  driver: EmailDriver,
  existing?: MessagingProvider,
  carry?: { fromAddress: string; fromName: string },
): EmailForm {
  const config: Record<string, string> = {};
  for (const [k, v] of Object.entries(existing?.config ?? {})) {
    if (!DEPRECATED_KEYS.includes(k) && v != null) config[k] = String(v);
  }
  let portTouched = false;
  if (driver === "SMTP") {
    const mode = resolveTlsMode(existing?.config ?? {});
    config.tlsMode = mode;
    const port = (config.port ?? "").trim();
    if (!port) config.port = String(defaultPort(mode));
    else portTouched = port !== String(defaultPort(mode));
  }
  return {
    driver,
    enabled: existing ? existing.enabled : true,
    fromAddress: existing ? existing.fromAddress ?? "" : carry?.fromAddress ?? "",
    fromName: existing ? existing.fromName ?? "" : carry?.fromName ?? "",
    config,
    portTouched,
    secret: { stored: !!existing?.secretSet, replacing: false, value: "" },
  };
}

/** Change the TLS mode; the port follows (587/465) unless the user typed one. */
export function setTlsMode(form: EmailForm, mode: TlsMode): EmailForm {
  const config = { ...form.config, tlsMode: mode };
  if (!form.portTouched) config.port = String(defaultPort(mode));
  return { ...form, config };
}

/** Set the port as typed. Clearing it hands the port back to the TLS mode. */
export function setPort(form: EmailForm, value: string): EmailForm {
  return { ...form, config: { ...form.config, port: value }, portTouched: value.trim() !== "" };
}

/** The PUT body. Never sends a deprecated key or an empty secret (a null secret keeps the stored one). */
export function toWrite(form: EmailForm): MessagingProviderWrite {
  const config: Record<string, string> = {};
  for (const [k, v] of Object.entries(form.config)) {
    const value = (v ?? "").trim();
    if (value && !DEPRECATED_KEYS.includes(k)) config[k] = value;
  }
  const wantsSecret = form.secret.replacing || !form.secret.stored;
  const secret = wantsSecret && form.secret.value.trim() !== "" ? form.secret.value : null;
  return {
    channel: "EMAIL",
    driver: form.driver,
    enabled: form.enabled,
    fromAddress: form.fromAddress.trim() || null,
    fromName: form.fromName.trim() || null,
    config,
    secret,
  };
}

/** True when saving would change what is stored. */
export function isDirty(form: EmailForm, baseline: EmailForm): boolean {
  return JSON.stringify(toWrite(form)) !== JSON.stringify(toWrite(baseline));
}

/**
 * One email address, no display name and no list: the shape the server accepts for fromAddress (it parses
 * with InternetAddress and requires the bare address) and for a test recipient.
 */
export function isEmailAddress(value: string): boolean {
  return /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+$/.test(value.trim()) && !value.trim().endsWith(".");
}

const HOST = /^[A-Za-z0-9.:[\]_-]+$/;
const EHLO = /^[A-Za-z0-9.-]{1,253}$/;
const ACCOUNT_ID = /^[A-Za-z0-9_-]{1,64}$/;
const PEM = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/;

function intInRange(raw: string | undefined, min: number, max: number): boolean | null {
  const value = (raw ?? "").trim();
  if (!value) return null;
  if (!/^\d+$/.test(value)) return false;
  const n = Number(value);
  return n >= min && n <= max;
}

function checkInt(config: Record<string, string>, key: string, min: number, max: number, message: string, errors: FieldErrors) {
  if (intInRange(config[key], min, max) === false) errors[`config.${key}`] = message;
}

function checkUrl(raw: string | undefined, field: string, httpsOnly: boolean, required: boolean, errors: FieldErrors) {
  const value = (raw ?? "").trim();
  if (!value) {
    if (required) errors[field] = "email.err.urlRequired";
    return;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    errors[field] = "email.err.urlInvalid";
    return;
  }
  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (!url.hostname || (scheme !== "https" && scheme !== "http")) errors[field] = "email.err.urlInvalid";
  else if (url.username || url.password) errors[field] = "email.err.urlCredentials";
  else if (httpsOnly && scheme !== "https") errors[field] = "email.err.httpsRequired";
  else if (httpsOnly && (url.search || url.hash || value.includes("?") || value.includes("#"))) errors[field] = "email.err.urlQuery";
}

function validateFrom(form: EmailForm, errors: FieldErrors) {
  if (form.driver === "LOG") return;
  const from = form.fromAddress.trim();
  if (!from) errors.fromAddress = "email.err.fromRequired";
  else if (!isEmailAddress(from)) errors.fromAddress = "email.err.fromInvalid";
  if (/[\r\n]/.test(form.fromName) || form.fromName.length > 200) errors.fromName = "email.err.fromName";
}

function validateSecret(form: EmailForm, errors: FieldErrors) {
  if (form.secret.stored && form.secret.replacing && !form.secret.value.trim()) errors.secret = "email.err.secretReplaceEmpty";
}

function validateSmtp(config: Record<string, string>, errors: FieldErrors) {
  const host = (config.host ?? "").trim();
  if (!host) errors["config.host"] = "email.err.hostRequired";
  else if (!HOST.test(host)) errors["config.host"] = "email.err.hostInvalid";
  checkInt(config, "port", 1, 65535, "email.err.port", errors);
  checkInt(config, "connectTimeoutMs", 100, 300_000, "email.err.timeout", errors);
  checkInt(config, "readTimeoutMs", 100, 300_000, "email.err.timeout", errors);
  const ehlo = (config.ehloName ?? "").trim();
  if (ehlo && !EHLO.test(ehlo)) errors["config.ehloName"] = "email.err.ehlo";
  validateCaBundle(config, errors);
}

function validateCloudflare(form: EmailForm, errors: FieldErrors) {
  const config = form.config;
  const account = (config.accountId ?? "").trim();
  if (!account) errors["config.accountId"] = "email.err.accountIdRequired";
  else if (!ACCOUNT_ID.test(account)) errors["config.accountId"] = "email.err.accountIdInvalid";
  const hasSecret = form.secret.stored || form.secret.value.trim() !== "";
  if (!hasSecret) errors.secret = "email.err.tokenRequired";
  checkUrl(config.baseUrl, "config.baseUrl", true, false, errors);
  checkInt(config, "connectTimeoutMs", 100, 300_000, "email.err.timeout", errors);
  checkInt(config, "readTimeoutMs", 100, 300_000, "email.err.timeout", errors);
  validateCaBundle(config, errors);
}

function validateCaBundle(config: Record<string, string>, errors: FieldErrors) {
  const bundle = (config.caBundle ?? "").trim();
  if (bundle && !PEM.test(bundle)) errors["config.caBundle"] = "email.err.caBundle";
}

/**
 * Validate the form before save, mirroring MessagingProviderValidator. One exception: tlsMode NONE is only
 * accepted by a server running with the dev profile, which the console cannot know, so the page explains it
 * and the server's answer is shown on the field.
 */
export function validateEmailForm(form: EmailForm): FieldErrors {
  const errors: FieldErrors = {};
  validateFrom(form, errors);
  switch (form.driver) {
    case "SMTP": validateSmtp(form.config, errors); break;
    case "CLOUDFLARE": validateCloudflare(form, errors); break;
    case "HTTP": checkUrl(form.config.url, "config.url", false, true, errors); break;
    default: break;
  }
  if (!errors.secret) validateSecret(form, errors);
  return errors;
}

/** The test recipient: one valid email address. Returns an i18n key, or null when valid. */
export function validateTestRecipient(to: string): string | null {
  if (!to.trim()) return "email.err.testToRequired";
  return isEmailAddress(to) ? null : "email.err.testToInvalid";
}

/** Split a 400's fieldErrors into those shown on this driver's fields and the rest (shown in a banner). */
export function splitServerErrors(driver: EmailDriver, fieldErrors: Record<string, string>): { fields: Record<string, string>; other: string[] } {
  const known = new Set(["fromAddress", "fromName", "secret", ...DRIVER_CONFIG_KEYS[driver].map((k) => `config.${k}`)]);
  const fields: Record<string, string> = {};
  const other: string[] = [];
  for (const [k, v] of Object.entries(fieldErrors)) {
    if (known.has(k)) fields[k] = v;
    else other.push(v);
  }
  return { fields, other };
}

/** The driver to open on: the enabled email provider, else a configured one, else SMTP. */
export function initialEmailDriver(providers: MessagingProvider[]): EmailDriver {
  const email = providers.filter((p) => p.channel === "EMAIL" && isEmailDriver(p.driver));
  const pick = email.find((p) => p.enabled) ?? email[0];
  return pick ? (pick.driver as EmailDriver) : "SMTP";
}

/** Enabled EMAIL providers other than `driver`. The server uses only one, so more than one is a mistake. */
export function otherEnabledEmailDrivers(providers: MessagingProvider[], driver: string): string[] {
  return providers.filter((p) => p.channel === "EMAIL" && p.enabled && p.driver !== driver).map((p) => p.driver);
}

export type TestTone = "success" | "info" | "warning" | "danger";

/** A test result ready to render: i18n keys for title/reason/guidance, the server's own text as data. */
export interface TestResultView {
  tone: TestTone;
  title: string;
  reason?: string;
  guidance?: string;
  message: string;
  diagnostic?: string;
  providerMessageId?: string;
}

const STATUS_TONE: Record<string, TestTone> = {
  ACCEPTED: "success",
  QUEUED: "info",
  PERMANENT_FAILURE: "danger",
  TRANSIENT_FAILURE: "warning",
};

const REASONS = ["RECIPIENT_BOUNCED", "MESSAGE_REJECTED", "AUTHENTICATION", "RATE_LIMITED", "PROVIDER_ERROR", "NETWORK", "CONFIGURATION", "NO_PROVIDER"];

function guidanceFor(driver: EmailDriver, reason: string | undefined, diagnostic: string | undefined): string | undefined {
  const authLike = reason === "AUTHENTICATION" || /\b(401|403)\b/.test(diagnostic ?? "");
  if (authLike) {
    if (driver === "CLOUDFLARE") return "email.test.guide.cloudflareAuth";
    if (driver === "SMTP") return "email.test.guide.smtpAuth";
    return "email.test.guide.httpAuth";
  }
  switch (reason) {
    case "NETWORK": return driver === "SMTP" ? "email.test.guide.smtpNetwork" : "email.test.guide.network";
    case "RATE_LIMITED": return "email.test.guide.rateLimited";
    case "RECIPIENT_BOUNCED": return "email.test.guide.bounced";
    case "MESSAGE_REJECTED": return driver === "CLOUDFLARE" ? "email.test.guide.cloudflareRejected" : "email.test.guide.rejected";
    case "CONFIGURATION": return "email.test.guide.configuration";
    case "PROVIDER_ERROR": return "email.test.guide.providerError";
    case "NO_PROVIDER": return "email.test.guide.noProvider";
    default: return undefined;
  }
}

/** Turn the test endpoint's answer into what the page shows. */
export function describeTestResult(r: TestResult, driver: EmailDriver): TestResultView {
  const status = r.result && STATUS_TONE[r.result] ? r.result : undefined;
  if (!status) {
    return {
      tone: r.sent ? "success" : "danger",
      title: r.sent ? "email.test.sent" : "email.test.notSent",
      message: r.message,
      guidance: !r.sent && /no enabled/i.test(r.message) ? "email.test.guide.noProvider" : undefined,
    };
  }
  const reason = r.reason && REASONS.includes(r.reason) ? r.reason : undefined;
  return {
    tone: STATUS_TONE[status],
    title: `email.test.status.${status}`,
    reason: reason ? `email.test.reason.${reason}` : undefined,
    guidance: guidanceFor(driver, reason, r.diagnostic),
    message: r.message,
    diagnostic: r.diagnostic || undefined,
    providerMessageId: r.providerMessageId || undefined,
  };
}
