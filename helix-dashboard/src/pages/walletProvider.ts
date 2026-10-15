/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// EUDI Wallet (OpenID4VP) identity provider — the console's form model: reading and writing the stored flat config
// map (WalletProviderConfig.fromStored / toStored on the server), validation that mirrors WalletConfigValidator, the
// advisory warnings the server has no channel for, and the mapping of a 400's fieldErrors onto the form. Pure
// functions only, unit-tested in walletProvider.test.ts. Messages and warnings are i18n keys; the page resolves them
// with t() (a server message that is not a key renders as itself).

/** The protocol names the server accepts for a wallet connection (case-insensitive). The console writes the first. */
export const WALLET_PROTOCOLS = ["eudi-wallet", "openid4vp", "wallet"];
export const WALLET_PROTOCOL = "eudi-wallet";

export function isWalletProtocol(protocol: string | null | undefined): boolean {
  return WALLET_PROTOCOLS.includes((protocol ?? "").trim().toLowerCase());
}

export const SD_JWT_FORMAT = "dc+sd-jwt";
export const MDOC_FORMAT = "mso_mdoc";
export const WALLET_FORMATS = [SD_JWT_FORMAT, MDOC_FORMAT];

export type ClientIdScheme = "x509_hash" | "x509_san_dns";
export type ResponseMode = "direct_post.jwt" | "direct_post";
export type SubjectStrategy = "ADMINISTRATIVE_NUMBER" | "ATTRIBUTE_TUPLE";
export type OnUnavailable = "FAIL_CLOSED" | "FAIL_OPEN_WITH_AUDIT";
/** Issuer X.509 certificate revocation (CRL / OCSP), TrustAnchors.RevocationMode on the server. */
export type RevocationChecking = "HARD_FAIL" | "SOFT_FAIL" | "OFF";
/** dcql.trustedAuthorities: "default" leaves the key unset, so the server's HAIP-profile default applies. */
export type TrustedAuthoritiesSetting = "default" | "on" | "off";
export const REVOCATION_MODES: readonly RevocationChecking[] = ["HARD_FAIL", "SOFT_FAIL", "OFF"];

/** Server bounds (WalletConfigValidator). */
export const TTL_RANGE = { min: 60, max: 900, default: 300 } as const;
export const STATUS_CACHE_RANGE = { min: 0, max: 900, default: 900 } as const;
/** The claim picker warns above this many claims (data minimisation). */
export const CLAIM_WARNING_THRESHOLD = 5;

export const ADMIN_NUMBER_CLAIM = "personal_administrative_number";
export const PLACE_OF_BIRTH_CLAIM = "place_of_birth";
export const DEFAULT_CLAIMS = ["given_name", "family_name", "birthdate"];

/** The eIDAS ladder the wallet's minimumLoa must be on (EidScheme.EUDI_WALLET delegates to it). */
export const LOA_LADDER = [
  { value: "http://eidas.europa.eu/LoA/low", key: "low" },
  { value: "http://eidas.europa.eu/LoA/substantial", key: "substantial" },
  { value: "http://eidas.europa.eu/LoA/high", key: "high" },
] as const;
export const DEFAULT_LOA = "http://eidas.europa.eu/LoA/high";

/** One requestable PID claim (GET /admin/realms/{r}/wallet/metadata). */
export interface PidClaimInfo {
  name: string;
  /** Whether an mdoc PID has an element for it (false: SD-JWT VC only). */
  mdoc: boolean;
}

/** What the form edits. Numbers stay strings so a blank field can mean "the server default". */
export interface WalletForm {
  accessKeyRef: string;
  clientIdScheme: ClientIdScheme;
  clientIdHost: string;
  /** Dev only: the chain of the raw private key (accessCertificatePrivateKey). */
  accessCertificateChain: string;
  trustAnchors: string;
  revocationChecking: RevocationChecking;
  credentialFormats: string[];
  requestedClaims: string[];
  subjectStrategy: SubjectStrategy;
  acknowledgeWeakSubject: boolean;
  minimumLoa: string;
  statusRequired: boolean;
  onUnavailable: OnUnavailable;
  statusMaxCacheSeconds: string;
  /** Free text: host names separated by commas, spaces or new lines. */
  statusAllowedHosts: string;
  responseMode: ResponseMode;
  transactionTtlSeconds: string;
  /** HAIP §5: the aki Trusted Authorities Query in the DCQL query (see trustedAuthoritiesEffective). */
  trustedAuthorities: TrustedAuthoritiesSetting;
}

export const DEFAULT_WALLET_FORM: WalletForm = {
  accessKeyRef: "",
  clientIdScheme: "x509_hash",
  clientIdHost: "",
  accessCertificateChain: "",
  trustAnchors: "",
  revocationChecking: "HARD_FAIL",
  credentialFormats: [...WALLET_FORMATS],
  requestedClaims: [...DEFAULT_CLAIMS],
  subjectStrategy: "ADMINISTRATIVE_NUMBER",
  acknowledgeWeakSubject: false,
  minimumLoa: DEFAULT_LOA,
  statusRequired: false,
  onUnavailable: "FAIL_CLOSED",
  statusMaxCacheSeconds: "",
  statusAllowedHosts: "",
  responseMode: "direct_post.jwt",
  transactionTtlSeconds: "",
  trustedAuthorities: "default",
};

/** The stored keys the form owns; any other stored key is carried over unchanged on save. */
export const WALLET_FORM_KEYS = [
  "accessKeyRef", "clientIdScheme", "clientIdHost", "accessCertificateChain", "trustAnchors", "revocationChecking",
  "credentialFormats",
  "pid.requestedClaims", "subject.strategy", "subject.acknowledgeWeakSubject", "minimumLoa", "statusList.required",
  "statusList.onUnavailable", "statusList.maxCacheSeconds", "statusList.allowedHosts", "responseMode",
  "transactionTtlSeconds", "dcql.trustedAuthorities",
];

/** The dev-only secret (ProviderSecretKeys): a raw PEM private key instead of an imported key. */
export const DEV_KEY = "accessCertificatePrivateKey";

// ---------------------------------------------------------------------------------------------------- reading

const text = (v: string | undefined) => (v ?? "").trim();

function list(raw: string | undefined, fallback: string[]): string[] {
  if (!text(raw)) return [...fallback];
  try {
    const parsed: unknown = JSON.parse(raw!);
    if (Array.isArray(parsed) && parsed.every((x) => typeof x === "string")) return parsed as string[];
  } catch {
    /* malformed: the server reports it; the form shows the default */
  }
  return [...fallback];
}

function pick<T extends string>(raw: string | undefined, values: readonly T[], fallback: T): T {
  const v = text(raw).toLowerCase();
  return values.find((x) => x.toLowerCase() === v) ?? fallback;
}

/** Wire value or enum name (X509_SAN_DNS, DIRECT_POST_JWT), as WalletProviderConfig reads them. */
function wire(raw: string | undefined): string {
  return text(raw).toLowerCase().replace(/_jwt$/, ".jwt");
}

/** The form for a stored config (absent keys take the server defaults). */
export function walletFormFromConfig(config: Record<string, string>): WalletForm {
  return {
    accessKeyRef: text(config.accessKeyRef),
    clientIdScheme: pick(wire(config.clientIdScheme), ["x509_hash", "x509_san_dns"] as const, "x509_hash"),
    clientIdHost: text(config.clientIdHost),
    accessCertificateChain: config.accessCertificateChain ?? "",
    trustAnchors: config.trustAnchors ?? "",
    revocationChecking: pick(config.revocationChecking, REVOCATION_MODES, "HARD_FAIL"),
    credentialFormats: list(config.credentialFormats, WALLET_FORMATS),
    requestedClaims: list(config["pid.requestedClaims"], DEFAULT_CLAIMS),
    subjectStrategy: pick(config["subject.strategy"], ["ADMINISTRATIVE_NUMBER", "ATTRIBUTE_TUPLE"] as const, "ADMINISTRATIVE_NUMBER"),
    acknowledgeWeakSubject: text(config["subject.acknowledgeWeakSubject"]).toLowerCase() === "true",
    minimumLoa: text(config.minimumLoa) || DEFAULT_LOA,
    statusRequired: text(config["statusList.required"]).toLowerCase() === "true",
    onUnavailable: pick(config["statusList.onUnavailable"], ["FAIL_CLOSED", "FAIL_OPEN_WITH_AUDIT"] as const, "FAIL_CLOSED"),
    statusMaxCacheSeconds: text(config["statusList.maxCacheSeconds"]),
    statusAllowedHosts: list(config["statusList.allowedHosts"], []).join(", "),
    responseMode: pick(wire(config.responseMode), ["direct_post.jwt", "direct_post"] as const, "direct_post.jwt"),
    transactionTtlSeconds: text(config.transactionTtlSeconds),
    trustedAuthorities: ({ true: "on", false: "off" } as Record<string, TrustedAuthoritiesSetting>)[
      text(config["dcql.trustedAuthorities"]).toLowerCase()] ?? "default",
  };
}

/**
 * Whether the server will send the aki trusted_authorities query (WalletProviderConfig.sendsTrustedAuthorities): an
 * explicit on/off wins; the default is on under the HAIP profile (x509_hash with direct_post.jwt) and off otherwise.
 */
export function trustedAuthoritiesEffective(form: WalletForm): boolean {
  if (form.trustedAuthorities !== "default") return form.trustedAuthorities === "on";
  return form.clientIdScheme === "x509_hash" && form.responseMode === "direct_post.jwt";
}

// ---------------------------------------------------------------------------------------------------- writing

/** Host names from free text (commas, spaces, new lines). */
export function parseHostList(value: string): string[] {
  return value.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);
}

/**
 * The stored flat map for a form: `base` (the stored config, so keys the form does not edit survive) with the form's
 * keys replaced. A blank optional value is left out, which the server reads as its default.
 */
export function walletConfigFromForm(form: WalletForm, base: Record<string, string> = {}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(base)) if (!WALLET_FORM_KEYS.includes(k)) out[k] = v;
  const put = (k: string, v: string) => { if (v.trim()) out[k] = v; };
  put("accessKeyRef", form.accessKeyRef.trim());
  out.clientIdScheme = form.clientIdScheme;
  if (form.clientIdScheme === "x509_san_dns") put("clientIdHost", form.clientIdHost.trim());
  put("accessCertificateChain", form.accessCertificateChain);
  put("trustAnchors", form.trustAnchors);
  out.revocationChecking = form.revocationChecking;
  out.credentialFormats = JSON.stringify(form.credentialFormats);
  out["pid.requestedClaims"] = JSON.stringify(form.requestedClaims);
  out["subject.strategy"] = form.subjectStrategy;
  out["subject.acknowledgeWeakSubject"] = String(form.acknowledgeWeakSubject);
  out.minimumLoa = form.minimumLoa;
  out["statusList.required"] = String(form.statusRequired);
  out["statusList.onUnavailable"] = form.onUnavailable;
  put("statusList.maxCacheSeconds", form.statusMaxCacheSeconds.trim());
  out["statusList.allowedHosts"] = JSON.stringify(parseHostList(form.statusAllowedHosts));
  out.responseMode = form.responseMode;
  put("transactionTtlSeconds", form.transactionTtlSeconds.trim());
  if (form.trustedAuthorities !== "default") out["dcql.trustedAuthorities"] = String(form.trustedAuthorities === "on");
  return out;
}

/** Whether two forms store the same settings (used for the unsaved-changes state). */
export function walletFormsEqual(a: WalletForm, b: WalletForm): boolean {
  return JSON.stringify(walletConfigFromForm(a)) === JSON.stringify(walletConfigFromForm(b));
}

// ---------------------------------------------------------------------------------------------------- validation

/** Field (stored key, as in the server's fieldErrors without "config.") → i18n key. */
export type WalletFieldErrors = Record<string, string>;

export interface WalletValidationContext {
  /** The server runs the dev profile (GET .../wallet/metadata). */
  devProfile: boolean;
  /** The PID claim catalogue; when absent, claim names are not checked here (the server still is). */
  pidClaims?: PidClaimInfo[];
  /** DNS SANs of the chosen key's leaf certificate, when the key is known. */
  keyDnsNames?: string[];
  /** The dev-only raw key: stored on the server, typed now (not saved), or marked for removal. */
  devKey?: { stored: boolean; pending: boolean; clearing: boolean };
}

/** WalletConfigValidator.HOST_NAME: a bare host name (no scheme, port or path). */
const HOST_NAME = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const WHOLE = /^-?\d+$/;

function inRange(value: string, min: number, max: number): boolean {
  const v = value.trim();
  if (!v) return true; // blank: the server default
  if (!WHOLE.test(v)) return false;
  const n = Number(v);
  return n >= min && n <= max;
}

/**
 * Field → i18n key for every rule the console can check before submit. Mirrors WalletConfigValidator (the rules that
 * need the key store, a parsed PEM or the query builder beyond the catalogue are left to the server, whose 400 is
 * mapped back onto the same fields). An empty object means the form may be saved.
 */
export function validateWallet(form: WalletForm, ctx: WalletValidationContext): WalletFieldErrors {
  const e: WalletFieldErrors = {};
  const add = (field: string, key: string) => { if (!(field in e)) e[field] = key; };

  // Access key: an imported key (accessKeyRef), or in dev only a raw key with its chain — never both.
  const hasRef = !!form.accessKeyRef.trim();
  const dev = ctx.devKey;
  const hasDevKey = !!dev && ((dev.stored && !dev.clearing) || dev.pending);
  if (hasDevKey && !ctx.devProfile) add(DEV_KEY, "wallet.err.devKeyOutsideDev");
  else if (hasRef && hasDevKey) add(DEV_KEY, "wallet.err.keyRefAndDevKey");
  else if (!hasRef && !hasDevKey) add("accessKeyRef", "wallet.err.accessKeyRequired");
  else if (hasDevKey && !form.accessCertificateChain.trim()) add("accessCertificateChain", "wallet.err.chainRequired");

  if (form.clientIdScheme === "x509_san_dns") {
    if (!form.clientIdHost.trim()) add("clientIdHost", "wallet.err.hostRequired");
    else if (sanCheck(form.clientIdHost, ctx.keyDnsNames) === "mismatch") add("clientIdHost", "wallet.err.hostNotInSan");
  }

  if (!form.trustAnchors.trim()) add("trustAnchors", "wallet.err.trustAnchorsRequired");
  else if (!form.trustAnchors.includes("-----BEGIN CERTIFICATE-----")) add("trustAnchors", "wallet.err.trustAnchorsPem");

  const formats = form.credentialFormats;
  let formatsOk = true;
  if (formats.length === 0) { add("credentialFormats", "wallet.err.formatsRequired"); formatsOk = false; }
  else if (formats.some((f) => !WALLET_FORMATS.includes(f))) { add("credentialFormats", "wallet.err.formatUnknown"); formatsOk = false; }
  else if (new Set(formats).size !== formats.length) { add("credentialFormats", "wallet.err.formatRepeated"); formatsOk = false; }

  const claims = form.requestedClaims;
  const known = ctx.pidClaims ? new Map(ctx.pidClaims.map((c) => [c.name, c.mdoc])) : null;
  if (claims.length === 0) add("pid.requestedClaims", "wallet.err.claimsRequired");
  else if (known && claims.some((c) => !known.has(c))) add("pid.requestedClaims", "wallet.err.claimUnknown");
  else if (new Set(claims).size !== claims.length) add("pid.requestedClaims", "wallet.err.claimRepeated");
  // DcqlQueryBuilder.pidQuery builds one query per format: an mdoc query with no mdoc claim is refused even when
  // dc+sd-jwt is requested too (the server's rule, not "either format will do").
  else if (known && formatsOk && formats.includes(MDOC_FORMAT)
    && !claims.some((c) => known.get(c))) add("pid.requestedClaims", "wallet.err.claimsNoMdoc");

  if (form.subjectStrategy === "ATTRIBUTE_TUPLE" && !form.acknowledgeWeakSubject) add("subject.strategy", "wallet.err.ackRequired");
  if (!LOA_LADDER.some((l) => l.value === form.minimumLoa)) add("minimumLoa", "wallet.err.loa");

  if (!inRange(form.statusMaxCacheSeconds, STATUS_CACHE_RANGE.min, STATUS_CACHE_RANGE.max)) {
    add("statusList.maxCacheSeconds", "wallet.err.cacheRange");
  }
  if (parseHostList(form.statusAllowedHosts).some((h) => !HOST_NAME.test(h))) add("statusList.allowedHosts", "wallet.err.allowedHosts");

  if (form.responseMode === "direct_post" && !ctx.devProfile) add("responseMode", "wallet.err.directPostDevOnly");
  if (!inRange(form.transactionTtlSeconds, TTL_RANGE.min, TTL_RANGE.max)) add("transactionTtlSeconds", "wallet.err.ttlRange");
  return e;
}

// ---------------------------------------------------------------------------------------------------- warnings

/** Advisory, never blocking: i18n suffixes under `wallet.warn.`. */
export type WalletWarning = "manyClaims" | "adminNumberWithoutStrategy" | "placeOfBirthOrphans" | "weakTuple" | "failOpen"
  | "revocationSoftFail" | "revocationOff";

/**
 * The warnings for a form. `original` is the stored form of an existing provider (null/undefined for a new one): adding
 * or removing place_of_birth changes every attribute-tuple subject of the provider, so existing tuple links stop
 * working (the recorded ruling in WalletProviderConfig.Subject).
 */
export function walletWarnings(form: WalletForm, original?: WalletForm | null): WalletWarning[] {
  const out: WalletWarning[] = [];
  if (form.requestedClaims.length > CLAIM_WARNING_THRESHOLD) out.push("manyClaims");
  if (form.requestedClaims.includes(ADMIN_NUMBER_CLAIM) && form.subjectStrategy !== "ADMINISTRATIVE_NUMBER") {
    out.push("adminNumberWithoutStrategy");
  }
  if (original && original.requestedClaims.includes(PLACE_OF_BIRTH_CLAIM) !== form.requestedClaims.includes(PLACE_OF_BIRTH_CLAIM)) {
    out.push("placeOfBirthOrphans");
  }
  if (form.subjectStrategy === "ATTRIBUTE_TUPLE") out.push("weakTuple");
  if (form.onUnavailable === "FAIL_OPEN_WITH_AUDIT") out.push("failOpen");
  if (form.revocationChecking === "SOFT_FAIL") out.push("revocationSoftFail");
  if (form.revocationChecking === "OFF") out.push("revocationOff");
  return out;
}

/** x509_san_dns: is the host one of the leaf's DNS SANs? "unknown" when the SANs are not known. */
export function sanCheck(host: string, dnsNames: string[] | undefined): "none" | "unknown" | "match" | "mismatch" {
  const h = host.trim().toLowerCase();
  if (!h) return "none";
  if (!dnsNames) return "unknown";
  return dnsNames.some((n) => n.toLowerCase() === h) ? "match" : "mismatch";
}

// ---------------------------------------------------------------------------------------------------- server errors

/** Which part of the form a field lives in: the detail page's tab, the wizard's step. In form order. */
export type WalletSection = "general" | "access" | "credentials" | "policies";

const SECTION_OF: Record<string, WalletSection> = {
  alias: "general", displayName: "general",
  accessKeyRef: "access", clientIdScheme: "access", clientIdHost: "access", accessCertificateChain: "access",
  [DEV_KEY]: "access",
  trustAnchors: "credentials", revocationChecking: "credentials", "dcql.trustedAuthorities": "credentials",
  credentialFormats: "credentials", "pid.requestedClaims": "credentials",
  "subject.strategy": "policies", minimumLoa: "policies", "statusList.required": "policies",
  "statusList.onUnavailable": "policies", "statusList.maxCacheSeconds": "policies", "statusList.allowedHosts": "policies",
  responseMode: "policies", transactionTtlSeconds: "policies",
};
const SECTION_ORDER: WalletSection[] = ["general", "access", "credentials", "policies"];

/** The stored field (error key) a form member is checked under, so editing it can clear that field's server error. */
const FIELD_OF: Record<keyof WalletForm, string> = {
  accessKeyRef: "accessKeyRef", clientIdScheme: "clientIdHost", clientIdHost: "clientIdHost",
  accessCertificateChain: "accessCertificateChain", trustAnchors: "trustAnchors",
  revocationChecking: "revocationChecking", credentialFormats: "credentialFormats",
  requestedClaims: "pid.requestedClaims", subjectStrategy: "subject.strategy", acknowledgeWeakSubject: "subject.strategy",
  minimumLoa: "minimumLoa", statusRequired: "statusList.required", onUnavailable: "statusList.onUnavailable",
  statusMaxCacheSeconds: "statusList.maxCacheSeconds", statusAllowedHosts: "statusList.allowedHosts",
  responseMode: "responseMode", transactionTtlSeconds: "transactionTtlSeconds",
  trustedAuthorities: "dcql.trustedAuthorities",
};

/** Drops the errors of the fields a form change touches (a server error stays until its field is edited). */
export function clearEditedErrors(errors: Record<string, string>, patch: Partial<WalletForm>): Record<string, string> {
  const touched = new Set(Object.keys(patch).map((k) => FIELD_OF[k as keyof WalletForm]));
  if (![...touched].some((f) => f in errors)) return errors;
  return Object.fromEntries(Object.entries(errors).filter(([k]) => !touched.has(k)));
}

/** The section holding the earliest error, or null when there is none. */
export function firstErrorSection(errors: Record<string, string>): WalletSection | null {
  const sections = Object.keys(errors).map((k) => SECTION_OF[k]).filter(Boolean);
  for (const s of SECTION_ORDER) if (sections.includes(s)) return s;
  return null;
}

/**
 * Splits a 400's fieldErrors (admin API names: `alias`, `displayName`, `config.<field>`, see
 * WalletConfigValidator.asAdminFields) into the errors shown on this form's fields and the rest (shown in a banner).
 * A clear flag (`config.clearAccessCertificatePrivateKey`) belongs to its secret's field.
 */
export function splitWalletServerErrors(fieldErrors: Record<string, string>): { fields: Record<string, string>; other: string[] } {
  const fields: Record<string, string> = {};
  const other: string[] = [];
  for (const [raw, message] of Object.entries(fieldErrors)) {
    let key = raw.startsWith("config.") ? raw.slice("config.".length) : raw;
    if (key === "clearAccessCertificatePrivateKey") key = DEV_KEY;
    if (SECTION_OF[key]) fields[key] = message;
    else other.push(message);
  }
  return { fields, other };
}

// ---------------------------------------------------------------------------------------------------- certificates

/** The CN of an RFC 2253 DN (`CN=verifier.example,O=Acme` → `verifier.example`), else the DN itself. */
export function commonName(dn: string): string {
  const m = /(?:^|,)\s*CN=((?:\\.|[^,])*)/i.exec(dn ?? "");
  return m ? m[1].replace(/\\(.)/g, "$1").trim() : (dn ?? "").trim();
}

/** "expired", "soon" (within 30 days) or "ok", for a certificate's notAfter. */
export function expiryState(notAfter: string, now: Date = new Date()): "expired" | "soon" | "ok" {
  const end = Date.parse(notAfter);
  if (Number.isNaN(end)) return "ok";
  if (end <= now.getTime()) return "expired";
  return end - now.getTime() < 30 * 24 * 3600 * 1000 ? "soon" : "ok";
}

// ---------------------------------------------------------------------------------------------------- key import

export interface KeyImportForm {
  name: string;
  privateKeyPem: string;
  certificateChainPem: string;
}

const KEY_NAME = /^[A-Za-z0-9._-]{1,64}$/;
const PRIVATE_KEY_BLOCK = /-----BEGIN (EC )?PRIVATE KEY-----/;

/**
 * The import form's checks before it is sent (the key store's own rules — curve, chain order, self-signed leaf, a taken
 * name, DB_ENCRYPTION — come back as a 400 on the same fields: name, privateKeyPem, certificateChainPem).
 */
export function validateKeyImport(form: KeyImportForm): WalletFieldErrors {
  const e: WalletFieldErrors = {};
  if (!form.name.trim()) e.name = "wallet.import.err.nameRequired";
  else if (!KEY_NAME.test(form.name.trim())) e.name = "wallet.import.err.nameFormat";
  if (!form.privateKeyPem.trim()) e.privateKeyPem = "wallet.import.err.keyRequired";
  else if (!PRIVATE_KEY_BLOCK.test(form.privateKeyPem)) e.privateKeyPem = "wallet.import.err.keyPem";
  if (!form.certificateChainPem.trim()) e.certificateChainPem = "wallet.import.err.chainRequired";
  else if (!form.certificateChainPem.includes("-----BEGIN CERTIFICATE-----")) e.certificateChainPem = "wallet.import.err.chainPem";
  return e;
}
