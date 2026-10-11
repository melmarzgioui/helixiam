/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import type { IdentityProviderConfig } from "./client";

/**
 * Identity-provider secrets are write-only (mirrors the backend's ProviderSecretKeys). The API never returns a secret:
 * it reports `"<key>Set": true|false` in `config` instead. On a write, an absent secret keeps the stored one, a value
 * replaces it, and `"clear<Key>": "true"` removes it.
 */
const OIDC = ["clientSecret"];
const EID = ["spDecryptionPrivateKey", "spSigningPrivateKey"];
const WALLET = ["accessCertificatePrivateKey", "subjectPepper"];
const LDAP = ["bindPassword", "bindPw", "bindCredential"];

const BY_PROTOCOL: Record<string, string[]> = {
  oidc: OIDC, social: OIDC, google: OIDC, microsoft: OIDC, github: OIDC,
  eid: EID, digid: EID, eherkenning: EID, eidas: EID,
  "eudi-wallet": WALLET, openid4vp: WALLET, wallet: WALLET,
  ldap: LDAP, ad: LDAP,
};

const ALL = new Set([...OIDC, ...EID, ...WALLET, ...LDAP]);

/** The secret keys of a protocol (case-insensitive); none for SAML or an unknown protocol. */
export function idpSecretKeys(protocol: string): string[] {
  return BY_PROTOCOL[protocol.toLowerCase()] ?? [];
}

/** A raw admin-API response: `config` may carry `<key>Set` booleans next to the string settings. */
export interface RawIdentityProviderConfig extends Omit<IdentityProviderConfig, "config" | "secretsSet"> {
  config?: Record<string, string | boolean>;
}

/** Splits the `<key>Set` flags out of a response's config into `secretsSet`, leaving a string-only config. */
export function fromIdpResponse(raw: RawIdentityProviderConfig): IdentityProviderConfig {
  const config: Record<string, string> = {};
  const secretsSet: Record<string, boolean> = {};
  for (const [k, v] of Object.entries(raw.config ?? {})) {
    const secret = k.endsWith("Set") ? k.slice(0, -3) : "";
    if (secret && ALL.has(secret)) secretsSet[secret] = v === true || v === "true";
    else config[k] = String(v);
  }
  return { ...raw, config, secretsSet };
}

/** The config to send: a blank secret is left out, so the stored one is kept (never wiped by an empty field). */
export function secretWriteConfig(config: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(config)) {
    if (ALL.has(k) && !(v ?? "").trim()) continue;
    out[k] = v;
  }
  return out;
}
