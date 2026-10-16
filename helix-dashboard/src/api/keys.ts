/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { adminJson } from "./adminError";

/** The leaf certificate's public facts (server RealmKeyView.CertificateInfo). */
export interface RealmKeyCertificate {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  sha256Fingerprint: string;
  selfSigned: boolean;
  chainLength: number;
  /** OK, EXPIRING (within 30 days) or EXPIRED. */
  expiry: "OK" | "EXPIRING" | "EXPIRED" | string;
}

/** A per-realm signing key as the Realm keys screen shows it. Public material only. */
export interface RealmKey {
  keyId: string;
  algorithm: "RS256" | "ES256" | string;
  status: "PENDING" | "ACTIVE" | "ROTATED" | "RETIRED" | string;
  publicKey: string | null;
  createdAt: number | null;
  rotatedAt: number | null;
  /** The JWK kid tokens carry. */
  kid?: string | null;
  source?: "GENERATED" | "IMPORTED" | "CSR" | string;
  activatedAt?: number | null;
  hasCsr?: boolean;
  publicKeyFingerprint?: string | null;
  certificate?: RealmKeyCertificate | null;
  /** PENDING keys: when the minimum staging time has passed (epoch ms). */
  activatableAt?: number | null;
}

/** The realm's signing algorithm choices (realm settings → Signing). */
export interface SigningSettings {
  defaultAlg: string;
  samlAlg: string;
  /** What the realm's ACTIVE keys can sign. */
  activeAlgorithms: string[];
}

export interface RealmKeyImport {
  privateKeyPem: string;
  certificateChainPem: string;
}

export interface RealmKeyCsrRequest {
  algorithm: string;
  subject: string;
  dnsNames: string[];
}

export interface RealmKeyApi {
  list(realmId: string): Promise<RealmKey[]>;
  rotate(realmId: string, algorithm?: string): Promise<RealmKey>;
  retire(realmId: string, keyId: string): Promise<void>;
  importKey(realmId: string, body: RealmKeyImport): Promise<RealmKey>;
  createCsr(realmId: string, body: RealmKeyCsrRequest): Promise<{ key: RealmKey; csrPem: string }>;
  csr(realmId: string, keyId: string): Promise<string>;
  attachCertificate(realmId: string, keyId: string, certificateChainPem: string): Promise<RealmKey>;
  activate(realmId: string, keyId: string, force?: boolean): Promise<RealmKey>;
  /** Whether the signed-in admin may change keys (realm-admin). */
  access(realmId: string): Promise<{ canManage: boolean }>;
  signingSettings(realmId: string): Promise<SigningSettings>;
  saveSigningSettings(realmId: string, body: { defaultAlg: string; samlAlg: string }): Promise<SigningSettings>;
}

/** HTTP-backed client for the realm signing-key admin API. Errors are AdminApiError (400 carries fieldErrors). */
export function createRealmKeyHttpClient(baseUrl = ""): RealmKeyApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, suffix = "") =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/keys${suffix}`;
  const send = <T>(u: string, method: string, body?: unknown) =>
    fetch(u, body === undefined ? { method } : {
      method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }).then((r) => adminJson<T>(r));
  const id = (keyId: string) => `/${encodeURIComponent(keyId)}`;
  return {
    list: (realmId) => send<RealmKey[]>(url(realmId), "GET"),
    rotate: (realmId, algorithm) => send<RealmKey>(url(realmId, "/rotate"), "POST", algorithm ? { algorithm } : {}),
    retire: (realmId, keyId) => send<null>(url(realmId, id(keyId)), "DELETE").then(() => undefined),
    importKey: (realmId, body) => send<RealmKey>(url(realmId, "/import"), "POST", body),
    createCsr: (realmId, body) => send<{ key: RealmKey; csrPem: string }>(url(realmId, "/csr"), "POST", body),
    csr: (realmId, keyId) => send<{ csrPem: string }>(url(realmId, `${id(keyId)}/csr`), "GET").then((b) => b.csrPem),
    attachCertificate: (realmId, keyId, certificateChainPem) =>
      send<RealmKey>(url(realmId, `${id(keyId)}/certificate`), "PUT", { certificateChainPem }),
    activate: (realmId, keyId, force) =>
      send<RealmKey>(url(realmId, `${id(keyId)}/activate${force ? "?force=true" : ""}`), "POST", {}),
    access: (realmId) => send<{ canManage: boolean }>(url(realmId, "/access"), "GET"),
    signingSettings: (realmId) =>
      send<SigningSettings>(`${base}/admin/realms/${encodeURIComponent(realmId)}/settings/signing`, "GET"),
    saveSigningSettings: (realmId, body) =>
      send<SigningSettings>(`${base}/admin/realms/${encodeURIComponent(realmId)}/settings/signing`, "PUT", body),
  };
}
