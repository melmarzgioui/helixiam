/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

/** A claim type from the realm's catalogue (E8.5 Claims/Client-scopes API). */
export interface Claim {
  realmId: string;
  claimId: string;
  key: string;
  label: string;
  placeholder: string | null;
  mandatory: boolean;
}

/** A client scope as the list/table shows it. */
export interface ClientScope {
  realmId: string;
  scopeId: string;
  name: string;
  description: string | null;
  claimCount: number;
  claimPreview: string[];
}

/** A client scope with its full claim list (detail page). */
export interface ScopeDetail {
  realmId: string;
  scopeId: string;
  name: string;
  description: string | null;
  claims: Claim[];
}

export interface ClaimWrite {
  key: string;
  label: string;
  placeholder?: string;
  mandatory: boolean;
}

/** Which catalogue claim populates the OIDC `sub` for a realm. `claimKey` defaults to `sub`. */
export interface SubjectClaim {
  realmId: string;
  claimKey: string;
}

export interface ClaimApi {
  list(realmId: string): Promise<Claim[]>;
  create(realmId: string, body: ClaimWrite): Promise<Claim>;
  update(realmId: string, claimId: string, body: ClaimWrite): Promise<Claim>;
  remove(realmId: string, claimId: string): Promise<void>;
  getSubject(realmId: string): Promise<SubjectClaim>;
  setSubject(realmId: string, claimKey: string): Promise<SubjectClaim>;
}

export interface ScopeApi {
  list(realmId: string): Promise<ClientScope[]>;
  get(realmId: string, scopeId: string): Promise<ScopeDetail>;
  create(realmId: string, body: { name: string; description?: string }): Promise<ClientScope>;
  remove(realmId: string, scopeId: string): Promise<void>;
  addClaim(realmId: string, scopeId: string, claimId: string): Promise<void>;
  removeClaim(realmId: string, scopeId: string, claimId: string): Promise<void>;
}

function json(res: Response) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.status === 204 ? null : res.json();
}
const send = (url: string, method: string, body?: unknown) =>
  fetch(url, body === undefined
    ? { method }
    : { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json);

/** HTTP-backed client for the E8.5 claim catalogue. */
export function createClaimHttpClient(baseUrl = ""): ClaimApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, claimId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/claims${claimId ? `/${encodeURIComponent(claimId)}` : ""}`;
  const subjectUrl = (realmId: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/subject-claim`;
  return {
    list: (realmId) => send(url(realmId), "GET"),
    create: (realmId, body) => send(url(realmId), "POST", body),
    update: (realmId, claimId, body) => send(url(realmId, claimId), "PUT", body),
    remove: (realmId, claimId) => send(url(realmId, claimId), "DELETE").then(() => undefined),
    getSubject: (realmId) => send(subjectUrl(realmId), "GET"),
    setSubject: (realmId, claimKey) => send(subjectUrl(realmId), "PUT", { claimKey }),
  };
}

/** HTTP-backed client for the E8.5 client scopes admin API. */
export function createScopeHttpClient(baseUrl = ""): ScopeApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, scopeId?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/client-scopes${scopeId ? `/${encodeURIComponent(scopeId)}` : ""}`;
  const claimUrl = (realmId: string, scopeId: string, claimId: string) =>
    `${url(realmId, scopeId)}/claims/${encodeURIComponent(claimId)}`;
  return {
    list: (realmId) => send(url(realmId), "GET"),
    get: (realmId, scopeId) => send(url(realmId, scopeId), "GET"),
    create: (realmId, body) => send(url(realmId), "POST", body),
    remove: (realmId, scopeId) => send(url(realmId, scopeId), "DELETE").then(() => undefined),
    addClaim: (realmId, scopeId, claimId) => send(claimUrl(realmId, scopeId, claimId), "PUT").then(() => undefined),
    removeClaim: (realmId, scopeId, claimId) => send(claimUrl(realmId, scopeId, claimId), "DELETE").then(() => undefined),
  };
}
