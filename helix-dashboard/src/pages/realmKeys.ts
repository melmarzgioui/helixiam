/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Realm signing keys (bring your own key / CSR / staged rollover) — the console's form model. Pure functions only,
// unit-tested in realmKeys.test.ts. Validation messages are i18n keys; a server message renders as itself.

import type { BadgeTone } from "../components/Badge";
import type { RealmKey, RealmKeyCertificate } from "../api/keys";
import { AdminApiError } from "../api/adminError";

export const ALGORITHMS = ["RS256", "ES256"] as const;
export const MAX_DNS_NAMES = 20;

export type Errors = Record<string, string>;

export interface ImportForm { privateKeyPem: string; certificateChainPem: string }
export interface CsrForm { algorithm: string; subject: string; dnsNames: string }
export interface CertificateForm { certificateChainPem: string }

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;
const DNS_NAME = /^(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
const DN_ATTRIBUTE = /^\s*[A-Za-z][A-Za-z0-9.]*\s*=\s*\S/;

/** The PEM block types in {@code text}, in order. */
export function pemBlockTypes(text: string): string[] {
  return Array.from(text.matchAll(PEM_BLOCK), (m) => m[1]);
}

export function hasPemBlock(text: string, type: string): boolean {
  return pemBlockTypes(text).includes(type);
}

const KEY_TYPES = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

function validateChainText(text: string): string | null {
  if (!text.trim()) return "realmKeys.v.chainRequired";
  const types = pemBlockTypes(text);
  if (types.length === 0 || types.some((t) => t !== "CERTIFICATE")) return "realmKeys.v.chainFormat";
  return null;
}

export function validateImport(form: ImportForm): Errors {
  const errors: Errors = {};
  const key = form.privateKeyPem.trim();
  if (!key) {
    errors.privateKeyPem = "realmKeys.v.keyRequired";
  } else {
    const types = pemBlockTypes(key);
    if (types.some((t) => t.includes("ENCRYPTED")) || /Proc-Type:\s*4,ENCRYPTED/.test(key)) {
      errors.privateKeyPem = "realmKeys.v.keyEncrypted";
    } else if (types.length !== 1 || !KEY_TYPES.includes(types[0])) {
      errors.privateKeyPem = "realmKeys.v.keyFormat";
    }
  }
  const chain = validateChainText(form.certificateChainPem);
  if (chain) errors.certificateChainPem = chain;
  return errors;
}

export function splitDnsNames(text: string): string[] {
  return text.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);
}

export function validateCsr(form: CsrForm): Errors {
  const errors: Errors = {};
  if (!(ALGORITHMS as readonly string[]).includes(form.algorithm)) errors.algorithm = "realmKeys.v.algorithm";
  const subject = form.subject.trim();
  if (!subject) {
    errors.subject = "realmKeys.v.subjectRequired";
  } else if (subject.length > 1024 || !subject.split(/(?<!\\),/).every((part) => DN_ATTRIBUTE.test(part))) {
    errors.subject = "realmKeys.v.subjectFormat";
  }
  const names = splitDnsNames(form.dnsNames);
  if (names.length > MAX_DNS_NAMES) {
    errors.dnsNames = "realmKeys.v.dnsTooMany";
  } else if (names.some((n) => n.length > 253 || !DNS_NAME.test(n))) {
    errors.dnsNames = "realmKeys.v.dnsName";
  }
  return errors;
}

export function validateCertificate(form: CertificateForm): Errors {
  const chain = validateChainText(form.certificateChainPem);
  return chain ? { certificateChainPem: chain } : {};
}

/** The server's field errors for the given form fields (400 {message, fieldErrors}). */
export function fieldErrorsFromServer(e: unknown, fields: string[]): Errors {
  if (!(e instanceof AdminApiError)) return {};
  const out: Errors = {};
  for (const f of fields) {
    if (e.fieldErrors[f]) out[f] = e.fieldErrors[f];
  }
  return out;
}

/** The CN of an RFC 2253 DN, unescaped; null without one. */
export function commonName(dn: string): string | null {
  for (const part of dn.split(/(?<!\\),/)) {
    const m = /^\s*CN\s*=\s*(.+)$/i.exec(part);
    if (m) return m[1].trim().replace(/\\(.)/g, "$1");
  }
  return null;
}

/** A human name for a key — never its id: the certificate CN, else "<alg> key from <date>". */
export type KeyLabel = { kind: "cn"; name: string } | { kind: "generated"; algorithm: string; date: string };

export function keyLabel(key: RealmKey, locale: string): KeyLabel {
  const cn = key.certificate ? commonName(key.certificate.subject) : null;
  if (cn) return { kind: "cn", name: cn };
  const date = key.createdAt
    ? new Date(key.createdAt).toLocaleDateString(locale === "nl" ? "nl-NL" : "en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })
    : "—";
  return { kind: "generated", algorithm: key.algorithm, date };
}

export function statusLabelKey(status: string): string {
  switch (status) {
    case "PENDING": return "realmKeys.status.pending";
    case "ACTIVE": return "realmKeys.status.active";
    case "ROTATED": return "realmKeys.status.retained";
    default: return "realmKeys.status.retired";
  }
}

export function statusTone(status: string): BadgeTone {
  switch (status) {
    case "ACTIVE": return "success";
    case "PENDING": return "accent";
    case "ROTATED": return "warning";
    default: return "neutral";
  }
}

export function daysUntil(epochMs: number, now: number = Date.now()): number {
  return Math.floor((epochMs - now) / 86_400_000);
}

export function expiryTone(cert: RealmKeyCertificate | null | undefined): BadgeTone | null {
  if (!cert) return null;
  if (cert.expiry === "EXPIRED") return "danger";
  if (cert.expiry === "EXPIRING") return "warning";
  return null;
}

export const canActivate = (k: RealmKey) => k.status === "PENDING";
export const canRetire = (k: RealmKey) => k.status === "PENDING" || k.status === "ROTATED";
export const canAttachCertificate = (k: RealmKey) => k.status === "PENDING" || k.status === "ACTIVE";

export function csrFileName(subject: string): string {
  const cn = commonName(subject);
  const safe = cn ? cn.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") : "";
  return `${safe || "realm-signing-key"}.csr`;
}
