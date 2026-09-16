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

/** Create/update payload. `secret` is write-only — omit/empty to keep the stored secret. */
export interface MessagingProviderWrite {
  channel: string;
  driver: string;
  enabled: boolean;
  fromAddress?: string | null;
  fromName?: string | null;
  config: Record<string, string>;
  secret?: string | null;
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

export interface TestResult { sent: boolean; message: string; }
export interface RenderedPreview { subject: string; body: string; }

export interface MessagingApi {
  listProviders(realmId: string): Promise<MessagingProvider[]>;
  saveProvider(realmId: string, body: MessagingProviderWrite): Promise<MessagingProvider>;
  deleteProvider(realmId: string, channel: string, driver: string): Promise<void>;
  testProvider(realmId: string, channel: string, to: string): Promise<TestResult>;
  listTemplates(realmId: string): Promise<MessageTemplate[]>;
  saveTemplate(realmId: string, body: MessageTemplate): Promise<MessageTemplate>;
  previewTemplate(realmId: string, subject: string | null, templateBody: string): Promise<RenderedPreview>;
}

/** HTTP-backed client for the N2 messaging admin REST API. */
export function createMessagingHttpClient(baseUrl = ""): MessagingApi {
  const base = baseUrl.replace(/\/$/, "");
  const root = (realmId: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}/messaging`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };
  const send = (url: string, method: string, body?: unknown) =>
    fetch(url, { method, headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) }).then(json);

  return {
    listProviders: (realmId) => fetch(`${root(realmId)}/providers`).then(json),
    saveProvider: (realmId, body) => send(`${root(realmId)}/providers`, "PUT", body),
    deleteProvider: (realmId, channel, driver) =>
      send(`${root(realmId)}/providers/${encodeURIComponent(channel)}/${encodeURIComponent(driver)}`, "DELETE").then(() => undefined),
    testProvider: (realmId, channel, to) =>
      send(`${root(realmId)}/providers/${encodeURIComponent(channel)}/test`, "POST", { to }),
    listTemplates: (realmId) => fetch(`${root(realmId)}/templates`).then(json),
    saveTemplate: (realmId, body) => send(`${root(realmId)}/templates`, "PUT", body),
    previewTemplate: (realmId, subject, templateBody) =>
      send(`${root(realmId)}/templates/preview`, "POST", { subject, body: templateBody }),
  };
}
