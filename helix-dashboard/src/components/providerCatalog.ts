/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { ProviderKind } from "./ProviderLogo";
import { LoaLevel } from "./LoaBadge";

export type ProtocolFamily = "oidc" | "saml" | "ldap";

/** One selectable assurance level for an eID scheme. */
export interface LoaOption {
  /** Stored in config.minimumLoa (the keyword the backend's EidLevelOfAssurance maps to a URN). */
  value: string;
  label: string;
  description?: string;
  /** Maps to a LoaLevel for the badge tone (low / substantial / high band). */
  band: LoaLevel;
}

export interface ProviderType {
  /** Stable id used as the connection's `providerType`. */
  id: string;
  kind: ProviderKind;
  name: string;
  description: string;
  protocol: ProtocolFamily;
  /** eID schemes carry a default LoA; generic protocols don't (for the badge tone). */
  defaultLoa?: LoaLevel;
  /** The scheme-specific assurance ladder (each eID is different). */
  loaOptions?: LoaOption[];
  /** Default selected LoA value (from loaOptions). */
  defaultLoaValue?: string;
  /** Whether the connection form should offer SAML metadata import. */
  metadataImport?: boolean;
}

// Each Dutch/EU eID has its own assurance ladder + URN family — surface the real rungs.
const DIGID_LOA: LoaOption[] = [
  { value: "loa1", label: "Basis (LoA 1)", description: "Username + password", band: "low" },
  { value: "loa2", label: "Midden (LoA 2)", description: "+ SMS or app one-time code", band: "substantial" },
  { value: "loa3", label: "Substantieel (LoA 3)", description: "DigiD app with document scan", band: "substantial" },
  { value: "loa4", label: "Hoog (LoA 4)", description: "Identity-document chip (NFC)", band: "high" },
];
const EHERKENNING_LOA: LoaOption[] = [
  { value: "loa2", label: "LoA 2 — low", description: "Username + password", band: "low" },
  { value: "loa3", label: "LoA 3 — substantial", description: "Two-factor (most services)", band: "substantial" },
  { value: "loa4", label: "LoA 4 — high", description: "PKIoverheid certificate", band: "high" },
];
const EIDAS_LOA: LoaOption[] = [
  { value: "low", label: "Low", description: "Single factor", band: "low" },
  { value: "substantial", label: "Substantial", description: "Two factors", band: "substantial" },
  { value: "high", label: "High", description: "Hardware-bound", band: "high" },
];

/** The catalogue the "Add identity provider" wizard offers in step 1. */
export const PROVIDER_TYPES: ProviderType[] = [
  { id: "oidc", kind: "oidc", name: "OpenID Connect", description: "Discovery, PKCE, refresh tokens", protocol: "oidc" },
  { id: "saml", kind: "saml", name: "SAML 2.0", description: "Metadata import, signed assertions", protocol: "saml", metadataImport: true },
  { id: "ldap", kind: "ldap", name: "LDAP / Active Directory", description: "Bind + user/group search", protocol: "ldap" },
  { id: "google", kind: "google", name: "Google", description: "Social login via Google Workspace", protocol: "oidc" },
  { id: "microsoft", kind: "microsoft", name: "Microsoft Entra ID", description: "Azure AD / Entra OIDC", protocol: "oidc" },
  { id: "github", kind: "github", name: "GitHub", description: "Social login for developers", protocol: "oidc" },
  { id: "apple", kind: "apple", name: "Apple", description: "Sign in with Apple", protocol: "oidc" },
  { id: "facebook", kind: "facebook", name: "Facebook", description: "Social login via Facebook", protocol: "oidc" },
  { id: "linkedin", kind: "linkedin", name: "LinkedIn", description: "Professional social login", protocol: "oidc" },
  { id: "instagram", kind: "instagram", name: "Instagram", description: "Social login via Instagram", protocol: "oidc" },
  { id: "twitter", kind: "twitter", name: "X (Twitter)", description: "Social login via X", protocol: "oidc" },
  { id: "gitlab", kind: "gitlab", name: "GitLab", description: "Social login for developers", protocol: "oidc" },
  { id: "bitbucket", kind: "bitbucket", name: "Bitbucket", description: "Social login for developers", protocol: "oidc" },
  { id: "paypal", kind: "paypal", name: "PayPal", description: "Social login via PayPal", protocol: "oidc" },
  { id: "stackoverflow", kind: "stackoverflow", name: "Stack Overflow", description: "Developer social login", protocol: "oidc" },
  { id: "openshift", kind: "openshift", name: "OpenShift", description: "OpenShift v4 OAuth", protocol: "oidc" },
  { id: "digid", kind: "digid", name: "DigiD (CombiConnect)", description: "NL citizen eID — BSN via EncryptedID", protocol: "saml", defaultLoa: "substantial", loaOptions: DIGID_LOA, defaultLoaValue: "loa3", metadataImport: true },
  { id: "eherkenning", kind: "eherkenning", name: "eHerkenning", description: "NL business eID — KvK number", protocol: "saml", defaultLoa: "substantial", loaOptions: EHERKENNING_LOA, defaultLoaValue: "loa3", metadataImport: true },
  { id: "eidas", kind: "eidas", name: "eIDAS (EU)", description: "Cross-border EU citizen login", protocol: "saml", defaultLoa: "substantial", loaOptions: EIDAS_LOA, defaultLoaValue: "substantial", metadataImport: true },
];

export function findProviderType(id: string): ProviderType | undefined {
  return PROVIDER_TYPES.find((p) => p.id === id);
}

/** The LoaLevel band (badge tone) for a stored LoA value within a provider type. */
export function loaBandOf(type: ProviderType | undefined, value: string | undefined): LoaLevel | undefined {
  if (!type) return undefined;
  const opt = type.loaOptions?.find((o) => o.value === value);
  return opt?.band ?? type.defaultLoa;
}

/**
 * Returns the keys of every still-empty required field for a connection (incl. alias / displayName).
 * An empty array means the Connection step is valid. SAML needs IdP metadata satisfiable by *either*
 * a metadata URL or an uploaded XML — that requirement surfaces under the synthetic key "metadata".
 */
export function missingConnectionFields(
  type: ProviderType,
  config: Record<string, string>,
  alias: string,
  displayName: string,
): string[] {
  const has = (k: string) => !!(config[k] ?? "").trim();
  const missing: string[] = [];
  if (!alias.trim()) missing.push("alias");
  if (!displayName.trim()) missing.push("displayName");
  if (type.protocol === "oidc") {
    if (!has("issuer")) missing.push("issuer");
    if (!has("clientId")) missing.push("clientId");
  }
  if (type.protocol === "saml") {
    if (!has("entityId")) missing.push("entityId");
    if (!has("metadataUrl") && !has("metadataXml")) missing.push("metadata");
  }
  if (type.protocol === "ldap") {
    if (!has("url")) missing.push("url");
    if (!has("bindDn")) missing.push("bindDn");
  }
  if (type.loaOptions && !has("minimumLoa")) missing.push("minimumLoa");
  return missing;
}

/** One attribute mapping: an IdP claim/attribute copied onto a user-profile field. */
export interface AttributeMapper {
  /** The IdP-side claim / SAML attribute / LDAP attribute name. */
  source: string;
  /** The Helix user-profile attribute it populates. */
  target: string;
}

/** The preset attribute mappers offered in step 3, keyed by protocol family. */
export const DEFAULT_MAPPERS: Record<ProtocolFamily, (AttributeMapper & { required?: boolean })[]> = {
  oidc: [
    { source: "sub", target: "username", required: true },
    { source: "email", target: "email" },
    { source: "given_name", target: "firstName" },
    { source: "family_name", target: "lastName" },
  ],
  saml: [
    { source: "NameID", target: "username", required: true },
    { source: "email", target: "email" },
    { source: "displayName", target: "displayName" },
  ],
  ldap: [
    { source: "uid", target: "username", required: true },
    { source: "mail", target: "email" },
    { source: "cn", target: "displayName" },
  ],
};
