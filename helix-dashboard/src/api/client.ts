/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { findProviderType } from "../components/providerCatalog";
import type { WizardResult } from "../components/ProviderWizard";

/** A persisted identity-provider connection (mirrors the backend E8.2 DTO). */
export interface IdentityProviderConfig {
  realmId: string;
  alias: string;
  protocol: string;
  displayName: string;
  enabled: boolean;
  config: Record<string, string>;
}

/** Create/update body (realm + alias come from the path, never the body). */
export interface IdentityProviderRequest {
  alias: string;
  protocol: string;
  displayName: string;
  enabled: boolean;
  config: Record<string, string>;
}

/** The admin API the console talks to. Backed by HTTP in the app, by memory in stories/tests. */
export interface IdentityProviderApi {
  list(realmId: string): Promise<IdentityProviderConfig[]>;
  get(realmId: string, alias: string): Promise<IdentityProviderConfig | null>;
  create(realmId: string, body: IdentityProviderRequest): Promise<IdentityProviderConfig>;
  update(realmId: string, alias: string, body: IdentityProviderRequest): Promise<IdentityProviderConfig>;
  remove(realmId: string, alias: string): Promise<void>;
  /** B10: trigger an on-demand LDAP/AD user sync for the named provider. */
  syncUsers(realmId: string, alias: string): Promise<LdapSyncResult>;
}

/** B10: outcome of an LDAP sync — users resolved to local accounts, failures, and any errors. */
export interface LdapSyncResult {
  synced: number;
  failed: number;
  errors: string[];
}

const EID_SCHEMES = new Set(["digid", "eherkenning", "eidas"]);

/**
 * Maps a wizard result to a create/update request. eID provider types carry their scheme as the
 * protocol (so the backend builds the right connector); everything else uses its protocol family.
 * The selected mappers are folded into the config map (the backend stores config as a flat map).
 */
export function toRequest(result: WizardResult): IdentityProviderRequest {
  const type = findProviderType(result.providerType);
  const protocol = EID_SCHEMES.has(result.providerType)
    ? result.providerType
    : type?.protocol ?? result.providerType;
  const mappers = result.mappers
    .filter((m) => m.source.trim() && m.target.trim())
    .map((m) => `${m.source.trim()}=${m.target.trim()}`)
    .join(",");
  return {
    alias: result.alias,
    protocol,
    displayName: result.displayName,
    enabled: result.enabled,
    // mappers fold into the flat config map as a `source=target,…` list (omitted when empty)
    config: { ...result.config, ...(mappers ? { mappers } : {}) },
  };
}

/**
 * Reverses a stored connection back into wizard state for editing. The serialised `source=target`
 * mappers list is parsed out of the flat config map; `protocol` doubles as the wizard's providerType
 * (eID schemes and protocol families both resolve via findProviderType).
 */
export function fromConfig(c: IdentityProviderConfig): WizardResult {
  const { mappers: serialised, ...config } = c.config;
  const mappers = (serialised ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((pair) => {
      const i = pair.indexOf("=");
      return i >= 0 ? { source: pair.slice(0, i), target: pair.slice(i + 1) } : { source: pair, target: pair };
    });
  return {
    providerType: c.protocol,
    alias: c.alias,
    displayName: c.displayName,
    config,
    mappers,
    enabled: c.enabled,
  };
}

/** HTTP-backed client for the E8.2 admin REST API. */
export function createHttpClient(baseUrl = ""): IdentityProviderApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, alias?: string) =>
    `${base}/admin/realms/${encodeURIComponent(realmId)}/identity-providers${alias ? `/${encodeURIComponent(alias)}` : ""}`;

  const json = async (res: Response) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.status === 204 ? null : res.json();
  };

  return {
    list: (realmId) => fetch(url(realmId)).then(json),
    get: (realmId, alias) =>
      fetch(url(realmId, alias)).then((res) => (res.status === 404 ? null : json(res))),
    create: (realmId, body) =>
      fetch(url(realmId), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    update: (realmId, alias, body) =>
      fetch(url(realmId, alias), { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(json),
    remove: (realmId, alias) => fetch(url(realmId, alias), { method: "DELETE" }).then(json).then(() => undefined),
    syncUsers: (realmId, alias) =>
      fetch(`${base}/admin/realms/${encodeURIComponent(realmId)}/user-federation/${encodeURIComponent(alias)}/sync`, { method: "POST" }).then(json),
  };
}

/** In-memory client — drives the Storybook story and the tests without a backend. */
export function createMemoryClient(seed: IdentityProviderConfig[] = []): IdentityProviderApi {
  const store = new Map<string, IdentityProviderConfig>();
  const key = (realmId: string, alias: string) => `${realmId}|${alias}`;
  seed.forEach((c) => store.set(key(c.realmId, c.alias), c));

  const save = (realmId: string, alias: string, body: IdentityProviderRequest): IdentityProviderConfig => {
    const config: IdentityProviderConfig = { realmId, ...body, alias };
    store.set(key(realmId, alias), config);
    return config;
  };

  return {
    list: async (realmId) => [...store.values()].filter((c) => c.realmId === realmId),
    get: async (realmId, alias) => store.get(key(realmId, alias)) ?? null,
    create: async (realmId, body) => save(realmId, body.alias, body),
    update: async (realmId, alias, body) => save(realmId, alias, body),
    remove: async (realmId, alias) => {
      store.delete(key(realmId, alias));
    },
    syncUsers: async () => ({ synced: 0, failed: 0, errors: [] }),
  };
}
