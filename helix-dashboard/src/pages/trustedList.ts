/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Trusted lists (EUDI wallet trust anchors from published, signed lists) — the console's form model: reading and
// writing a source, validation that mirrors TrustedListConfigValidator on the server, the presets for the lists that
// are actually published, and the status → badge mapping. Pure functions only, unit-tested in trustedList.test.ts.
// Messages are i18n keys; a server message that is not a key renders as itself.

import type { BadgeTone } from "../components/Badge";
import type { TrustedList, TrustedListFormat, TrustedListStatus, TrustedListWrite } from "../api/trustedLists";

export const GRANTED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
export const RECOGNISED = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel";
export const STATUS_OPTIONS = [
  { value: GRANTED, key: "granted" },
  { value: RECOGNISED, key: "recognised" },
] as const;
export const GRACE_RANGE = { min: 0, max: 720, default: 24 } as const;

export interface TrustedListForm {
  name: string;
  url: string;
  format: TrustedListFormat;
  signerCertificates: string;
  /** Free text: one URI per line (commas and spaces also separate). */
  serviceTypes: string;
  acceptedStatuses: string[];
  /** Free text: two-letter territory codes. */
  territories: string;
  graceHours: string;
  enabled: boolean;
}

export const DEFAULT_TRUSTED_LIST_FORM: TrustedListForm = {
  name: "",
  url: "",
  format: "ETSI_119612_XML",
  signerCertificates: "",
  serviceTypes: "",
  acceptedStatuses: [GRANTED, RECOGNISED],
  territories: "",
  graceHours: String(GRACE_RANGE.default),
  enabled: true,
};

/**
 * Lists that are published today (checked 2026-10-15). A preset fills the URL, format and service types only: the
 * signer certificate must come from the publisher (never from the list itself).
 */
export const TRUSTED_LIST_PRESETS: readonly { id: string; url: string; format: TrustedListFormat; serviceTypes: string[] }[] = [
  { id: "eudiTestLotl", url: "https://trustedlist.serviceproviders.eudiw.dev/LOTL/01.xml", format: "ETSI_119612_XML",
    serviceTypes: ["http://uri.etsi.org/Svc/Svctype/Provider/PID"] },
  { id: "ecPidLote", url: "https://acceptance.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json",
    format: "ETSI_119602_JSON", serviceTypes: ["http://uri.etsi.org/19602/SvcType/PID/Issuance"] },
  { id: "euLotl", url: "https://ec.europa.eu/tools/lotl/eu-lotl.xml", format: "ETSI_119612_XML",
    serviceTypes: ["http://uri.etsi.org/TrstSvc/Svctype/CA/QC"] },
];

/** Values from free text: new lines, commas and spaces separate. */
export function splitLines(text: string): string[] {
  return text.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);
}

export function applyPreset(form: TrustedListForm, id: string): TrustedListForm {
  const p = TRUSTED_LIST_PRESETS.find((x) => x.id === id);
  return p ? { ...form, url: p.url, format: p.format, serviceTypes: p.serviceTypes.join("\n") } : form;
}

export function formFromTrustedList(l: TrustedList): TrustedListForm {
  return {
    name: l.name,
    url: l.url,
    format: l.format,
    signerCertificates: l.signerCertificates,
    serviceTypes: l.serviceTypes.join("\n"),
    acceptedStatuses: [...(l.acceptedStatuses.length ? l.acceptedStatuses : l.effectiveStatuses)],
    territories: l.territories.join(" "),
    graceHours: String(l.graceHours),
    enabled: l.enabled,
  };
}

export function trustedListWrite(f: TrustedListForm): TrustedListWrite {
  return {
    name: f.name.trim(),
    url: f.url.trim(),
    format: f.format,
    signerCertificates: f.signerCertificates,
    serviceTypes: splitLines(f.serviceTypes),
    acceptedStatuses: [...f.acceptedStatuses],
    territories: splitLines(f.territories).map((t) => t.toUpperCase()),
    graceHours: Number(f.graceHours.trim()),
    enabled: f.enabled,
  };
}

const NAME = /^[A-Za-z0-9._-]{1,64}$/;
const URI = /^(https?|urn):\S+$/i;
const TERRITORY = /^[A-Z]{2}$/;

function httpsUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "https:" && !!u.hostname && !u.username && !u.password && !u.hash;
  } catch {
    return false;
  }
}

/** Field → i18n key for every rule the console checks before saving (the server checks the same and more). */
export function validateTrustedList(f: TrustedListForm): Record<string, string> {
  const e: Record<string, string> = {};
  const name = f.name.trim();
  if (!name) e.name = "tl.err.nameRequired";
  else if (!NAME.test(name)) e.name = "tl.err.nameFormat";
  const url = f.url.trim();
  if (!url) e.url = "tl.err.urlRequired";
  else if (!httpsUrl(url)) e.url = "tl.err.urlHttps";
  if (!f.signerCertificates.trim()) e.signerCertificates = "tl.err.signerRequired";
  else if (!f.signerCertificates.includes("-----BEGIN CERTIFICATE-----")) e.signerCertificates = "tl.err.signerPem";
  const types = splitLines(f.serviceTypes);
  if (types.length === 0) e.serviceTypes = "tl.err.typesRequired";
  else if (types.length > 20 || types.some((t) => !URI.test(t)) || new Set(types).size !== types.length) {
    e.serviceTypes = "tl.err.typesFormat";
  }
  if (f.acceptedStatuses.length === 0) e.acceptedStatuses = "tl.err.statusRequired";
  const territories = splitLines(f.territories).map((t) => t.toUpperCase());
  if (territories.some((t) => !TERRITORY.test(t)) || new Set(territories).size !== territories.length) {
    e.territories = "tl.err.territories";
  }
  const grace = f.graceHours.trim();
  if (!/^\d+$/.test(grace) || Number(grace) < GRACE_RANGE.min || Number(grace) > GRACE_RANGE.max) e.graceHours = "tl.err.grace";
  return e;
}

export function statusTone(status: TrustedListStatus | string): BadgeTone {
  switch (status) {
    case "OK": return "success";
    case "FAILING":
    case "STALE": return "warning";
    case "EXPIRED":
    case "ERROR": return "danger";
    default: return "neutral";
  }
}
