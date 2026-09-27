/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A configured messaging provider (SMS / EMAIL / PUSH). Secrets are masked: `secretSet` only reports
 *  whether one is stored. (Helix notifications N4) */
export interface MessagingProvider {
  id: string;
  realmId: string;
  channel: "SMS" | "EMAIL" | "PUSH";
  driver: string;
  enabled: boolean;
  fromAddress: string | null;
  fromName: string | null;
  config: Record<string, string>;
  secretSet: boolean;
}

/**
 * Create/update payload. `secret` is write-only: absent, null or blank keeps the stored secret, a value replaces it,
 * and `clearSecret: true` (without a secret) removes it. `config` replaces the stored config as a whole. For EMAIL,
 * saving with `enabled: true` makes this the realm's only enabled email provider (the server turns the others off);
 * the response is only the saved provider, so re-read the list.
 */
export interface MessagingProviderWrite {
  channel: string;
  driver: string;
  enabled: boolean;
  fromAddress?: string | null;
  fromName?: string | null;
  config: Record<string, string>;
  secret?: string | null;
  clearSecret?: boolean;
}

/** A per-realm message template. `subject` applies to email only. */
export interface MessageTemplate {
  id: string | null;
  realmId: string;
  templateKey: string;
  channel: "SMS" | "EMAIL" | "PUSH";
  subject: string | null;
  body: string;
  enabled: boolean;
  /** Email only: when true the body is authored + delivered as HTML. */
  html: boolean;
}

/**
 * Outcome of a test send. For EMAIL the server also returns the classified delivery `result`
 * (ACCEPTED | QUEUED | PERMANENT_FAILURE | TRANSIENT_FAILURE), its `reason` (e.g. AUTHENTICATION,
 * RECIPIENT_BOUNCED, NETWORK), a one-line `diagnostic` that never contains the secret, and the
 * provider's message id. They are absent for SMS and PUSH, and when nothing was sent at all.
 */
export interface TestResult {
  sent: boolean;
  message: string;
  result?: string;
  reason?: string;
  diagnostic?: string;
  providerMessageId?: string;
  /** The driver that was tested (EMAIL). */
  driver?: string;
}

/**
 * A failed admin call. On a 400 the server answers `{message, fieldErrors}` (AdminValidationAdvice); the
 * field keys are `channel`, `driver`, `fromAddress`, `fromName`, `secret` and `config.<key>`.
 */
export class MessagingApiError extends Error {
  constructor(message: string, readonly status: number, readonly fieldErrors: Record<string, string> = {}) {
    super(message);
    this.name = "MessagingApiError";
  }
}
export interface RenderedPreview { subject: string; body: string; }

export interface MessagingApi {
  listProviders(realmId: string): Promise<MessagingProvider[]>;
  saveProvider(realmId: string, body: MessagingProviderWrite): Promise<MessagingProvider>;
  deleteProvider(realmId: string, channel: string, driver: string): Promise<void>;
  /** Send a test through the realm's active provider, or, with `driver`, through that provider even when it is off. */
  testProvider(realmId: string, channel: string, to: string, driver?: string): Promise<TestResult>;
  listTemplates(realmId: string): Promise<MessageTemplate[]>;
  saveTemplate(realmId: string, body: MessageTemplate): Promise<MessageTemplate>;
  previewTemplate(realmId: string, subject: string | null, templateBody: string, html?: boolean): Promise<RenderedPreview>;
}

/** HTTP-backed client for the N2 messaging admin REST API. */
export function createMessagingHttpClient(baseUrl = ""): MessagingApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}/messaging`;

  const json = async (res: Response) => {
    if (!res.ok) {
      let message = `${res.status} ${res.statusText}`;
      let fieldErrors: Record<string, string> = {};
      try {
        const body = await res.json();
        if (body && typeof body.message === "string") message = body.message;
        if (body && body.fieldErrors && typeof body.fieldErrors === "object") fieldErrors = body.fieldErrors;
      } catch {
        /* non-JSON error body: keep the status line */
      }
      throw new MessagingApiError(message, res.status, fieldErrors);
    }
    return res.status === 204 ? null : res.json();
  };
  const send = (url: string, method: string, body?: unknown) =>
    fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).then(json);

  return {
    listProviders: (realmId) => fetch(`${root(realmId)}/providers`).then(json),
    saveProvider: (realmId, body) => send(`${root(realmId)}/providers`, "PUT", body),
    deleteProvider: (realmId, channel, driver) =>
      send(`${root(realmId)}/providers/${encodeURIComponent(channel)}/${encodeURIComponent(driver)}`, "DELETE").then(() => undefined),
    testProvider: (realmId, channel, to, driver) =>
      send(`${root(realmId)}/providers/${encodeURIComponent(channel)}/test`, "POST", driver ? { to, driver } : { to }),
    listTemplates: (realmId) => fetch(`${root(realmId)}/templates`).then(json),
    saveTemplate: (realmId, body) => send(`${root(realmId)}/templates`, "PUT", body),
    previewTemplate: (realmId, subject, templateBody, html) =>
      send(`${root(realmId)}/templates/preview`, "POST", { subject, body: templateBody, html: html ?? false }),
  };
}
