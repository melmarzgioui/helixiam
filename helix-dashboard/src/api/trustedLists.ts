/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { AdminApiError, adminJson } from "./adminError";
import type { CertificateInfo } from "./wallet";

export type TrustedListFormat = "ETSI_119612_XML" | "ETSI_119602_JSON";
/** TrustedListHealth.Status on the server, evaluated now. */
export type TrustedListStatus = "NEVER" | "ERROR" | "OK" | "FAILING" | "STALE" | "EXPIRED" | "DISABLED";

/** A trusted list source of the realm (server TrustedListView). Times are ISO-8601 or null. */
export interface TrustedList {
  id: string;
  name: string;
  url: string;
  format: TrustedListFormat;
  signerCertificates: string;
  signers: CertificateInfo[];
  serviceTypes: string[];
  /** As configured (empty: the default statuses). */
  acceptedStatuses: string[];
  /** What counts now: the configured statuses, or the defaults. */
  effectiveStatuses: string[];
  territories: string[];
  graceHours: number;
  enabled: boolean;
  status: TrustedListStatus;
  /** Whether wallet providers use this source's anchors right now. */
  anchorsInUse: boolean;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  listIssuedAt: string | null;
  nextUpdate: string | null;
  anchorsUsableUntil: string | null;
  nextRefreshAt: string | null;
  sequenceNumber: number | null;
  listsRead: number | null;
  lastError: string | null;
  serviceCount: number;
  anchorCount: number;
}

/** One verified service of the last good list (server TrustedListAnchorView). */
export interface TrustedListAnchor {
  subject: string;
  issuer: string;
  serialNumber: string;
  notAfter: string;
  serviceName: string | null;
  provider: string | null;
  country: string | null;
  serviceType: string;
  status: string | null;
  usable: boolean;
  problem: string | null;
}

export interface TrustedListWrite {
  name: string;
  url: string;
  format: TrustedListFormat;
  signerCertificates: string;
  serviceTypes: string[];
  acceptedStatuses: string[];
  territories: string[];
  graceHours: number;
  enabled: boolean;
}

/** The admin API behind the Trusted lists screen. Errors are AdminApiError (400 carries fieldErrors, 409 = busy). */
export interface TrustedListApi {
  list(realmId: string): Promise<TrustedList[]>;
  get(realmId: string, id: string): Promise<TrustedList>;
  anchors(realmId: string, id: string): Promise<TrustedListAnchor[]>;
  create(realmId: string, body: TrustedListWrite): Promise<TrustedList>;
  update(realmId: string, id: string, body: TrustedListWrite): Promise<TrustedList>;
  remove(realmId: string, id: string): Promise<void>;
  refresh(realmId: string, id: string): Promise<TrustedList>;
}

export function createTrustedListHttpClient(baseUrl = ""): TrustedListApi {
  const base = baseUrl.replace(/\/$/, "");
  const url = (realmId: string, id?: string, sub?: string) => `${base}/admin/realms/${encodeURIComponent(realmId)}`
    + `/trusted-lists${id ? `/${encodeURIComponent(id)}` : ""}${sub ? `/${sub}` : ""}`;
  const send = (u: string, method: string, body?: unknown) => fetch(u, body === undefined ? { method }
    : { method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  return {
    list: (realmId) => fetch(url(realmId)).then((r) => adminJson<TrustedList[]>(r)),
    get: (realmId, id) => fetch(url(realmId, id)).then((r) => adminJson<TrustedList>(r)),
    anchors: (realmId, id) => fetch(url(realmId, id, "anchors")).then((r) => adminJson<TrustedListAnchor[]>(r)),
    create: (realmId, body) => send(url(realmId), "POST", body).then((r) => adminJson<TrustedList>(r)),
    update: (realmId, id, body) => send(url(realmId, id), "PUT", body).then((r) => adminJson<TrustedList>(r)),
    remove: (realmId, id) => send(url(realmId, id), "DELETE").then((r) => adminJson<void>(r)),
    refresh: (realmId, id) => send(url(realmId, id, "refresh"), "POST", {}).then((r) => adminJson<TrustedList>(r)),
  };
}

/** In-memory client for stories, tests and the screenshot harness. Refresh marks the source OK with `anchors`. */
export function createTrustedListMemoryClient(opts: { lists?: TrustedList[]; anchors?: TrustedListAnchor[] } = {}): TrustedListApi {
  const lists = [...(opts.lists ?? [])];
  const anchors = opts.anchors ?? [];
  const find = (id: string) => {
    const l = lists.find((x) => x.id === id);
    if (!l) throw new AdminApiError("Not found", 404);
    return l;
  };
  const fromWrite = (id: string, b: TrustedListWrite, prev?: TrustedList): TrustedList => ({
    ...(prev ?? sampleTrustedList({ status: "NEVER", anchorsInUse: false, serviceCount: 0, anchorCount: 0,
      lastAttemptAt: null, lastSuccessAt: null, listIssuedAt: null, nextUpdate: null, anchorsUsableUntil: null,
      nextRefreshAt: null, sequenceNumber: null, listsRead: null, lastError: null })),
    ...b, id, effectiveStatuses: b.acceptedStatuses,
  });
  return {
    list: async () => [...lists],
    get: async (_r, id) => find(id),
    anchors: async (_r, id) => (find(id).status === "NEVER" ? [] : anchors),
    create: async (_r, b) => {
      if (lists.some((l) => l.name === b.name)) {
        throw new AdminApiError("taken", 400, { name: `A trusted list named '${b.name}' already exists in this realm` });
      }
      const l = fromWrite(`tl-${lists.length + 1}`, b);
      lists.push(l);
      return l;
    },
    update: async (_r, id, b) => {
      const i = lists.findIndex((x) => x.id === id);
      lists[i] = fromWrite(id, b, lists[i]);
      return lists[i];
    },
    remove: async (_r, id) => { lists.splice(lists.findIndex((x) => x.id === id), 1); },
    refresh: async (_r, id) => {
      const i = lists.findIndex((x) => x.id === id);
      const now = new Date();
      lists[i] = { ...lists[i], status: "OK", anchorsInUse: true, lastError: null, lastAttemptAt: now.toISOString(),
        lastSuccessAt: now.toISOString(), anchorCount: anchors.filter((a) => a.usable).length, serviceCount: anchors.length };
      return lists[i];
    },
  };
}

/** A plausible source for stories (the EUDI reference implementation's test LOTL, refreshed and healthy). */
export function sampleTrustedList(over: Partial<TrustedList> = {}): TrustedList {
  return {
    id: "tl-1", name: "eudi-test-lotl", url: "https://trustedlist.serviceproviders.eudiw.dev/LOTL/01.xml",
    format: "ETSI_119612_XML", signerCertificates: "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n",
    signers: [], serviceTypes: ["http://uri.etsi.org/Svc/Svctype/Provider/PID"], acceptedStatuses: [],
    effectiveStatuses: ["http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
      "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"],
    territories: [], graceHours: 24, enabled: true, status: "OK", anchorsInUse: true,
    lastAttemptAt: "2026-10-15T08:00:00Z", lastSuccessAt: "2026-10-15T08:00:00Z", listIssuedAt: "2026-04-30T14:28:34Z",
    nextUpdate: "2026-10-27T14:28:34Z", anchorsUsableUntil: "2026-10-28T14:28:34Z", nextRefreshAt: "2026-10-15T14:00:00Z",
    sequenceNumber: 2, listsRead: 17, lastError: null, serviceCount: 33, anchorCount: 29,
    ...over,
  };
}
